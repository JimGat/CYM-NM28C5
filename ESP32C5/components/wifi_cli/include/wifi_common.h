#ifndef WIFI_COMMON_H
#define WIFI_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "led_strip.h"

#ifdef __cplusplus
extern "C" {
#endif

// Version — defined by CMakeLists.txt (PROJECT_VER) and injected as a compile
// definition.  Edit the version in CMakeLists.txt only; do not hardcode here.
#ifndef FW_VERSION
#define FW_VERSION "unknown"
#endif

// Maximum limits
// CYD port (classic ESP32, no PSRAM): halved vs C5 to fit DRAM budget.
// wifi_ap_record_t is 92B — MAX_SCAN_RESULTS 128→64 saves 5.9KB of static DRAM.
#define MAX_AP_CNT 64
// CYD port: 30 results (was 40) — saves 1KB static DRAM on 240x320 UI.
#define MAX_SCAN_RESULTS 30
#define MAX_PROBES 100
#define MAX_CLIENTS_PER_AP 24
#define MAX_TARGET_BSSIDS 24
#define MAX_WHITELIST_ENTRIES 48
#define MAX_SNIFFER_APS 48
#define MAX_PROBE_REQUESTS 100
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 512
#define MAX_HTML_FILES 12
#define MAX_HTML_FILENAME 48

// GPIO pins
#define NEOPIXEL_GPIO 27   // CYD has no WS2812 by default — wire one to GPIO27 or leave unconnected (harmless)
#define LED_COUNT 1
#define RMT_RES_HZ (10 * 1000 * 1000)

// GPS UART pins — CYD: wire GPS TX->GPIO16(RX), GPS RX->GPIO17(TX) on P3 header
#define GPS_UART_NUM UART_NUM_1
#define GPS_TX_PIN 17
#define GPS_RX_PIN 16
#define GPS_BUF_SIZE 512

// SD Card SPI pins — ESP32-2432S028R (CYD, shares HSPI/SPI2_HOST with touch on stock board,
// but on CYM-port the touch gets its own bus; SD keeps the classic CYD SPI2 pins)
#define SD_MISO_PIN 19
#define SD_MOSI_PIN 23
#define SD_CLK_PIN  18
#define SD_CS_PIN   5

// Application states
typedef enum {
    APP_STATE_IDLE = 0,
    APP_STATE_DEAUTH,
    APP_STATE_DEAUTH_EVIL_TWIN,
    APP_STATE_EVIL_TWIN_PASS_CHECK,
    APP_STATE_DRAGON_DRAIN,
    APP_STATE_SAE_OVERFLOW,
    APP_STATE_BLACKOUT,
    APP_STATE_KARMA,
    APP_STATE_PORTAL,
    APP_STATE_SNIFFER,
    APP_STATE_SNIFFER_DOG,
    APP_STATE_WARDRIVE
} app_state_t;

// Scan result structure
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    bool selected;
} scan_result_t;

// Probe request structure
typedef struct {
    uint8_t mac[6];
    char ssid[33];
    int rssi;
    uint32_t last_seen;
} probe_request_t;

// Sniffer client structure
typedef struct {
    uint8_t mac[6];
    int rssi;
    uint32_t last_seen;
} sniffer_client_t;

// Client info structure (alias for compatibility)
typedef sniffer_client_t client_info_t;

// Sniffer AP structure
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    sniffer_client_t clients[MAX_CLIENTS_PER_AP];
    int client_count;
    uint32_t last_seen;
} sniffer_ap_t;

// GPS data structure
typedef struct {
    float latitude;
    float longitude;
    float altitude;
    float accuracy;
    int satellites;
    bool valid;
    char time_utc[10];  /* "HH:MM:SS" from GGA field 1, empty if no fix */
    float speed;        /* ground speed in m/s from RMC field 7 (SOG, knots->m/s); 0 when no fix */
} gps_data_t;

// Target BSSID structure
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    uint32_t last_seen;
    bool active;
} target_bssid_t;

// Global LED strip handle (shared across components)
extern led_strip_handle_t g_led_strip;

// Global application state (shared across components)
extern volatile app_state_t g_app_state;

// Global stop flag (shared across components)
extern volatile bool g_operation_stop_requested;

// Global TX power mode flag (shared across all WiFi/BLE components)
extern bool g_max_power_mode;

// Apply WiFi TX power and power-save settings for the current mode.
// Call after every esp_wifi_start() — safe to call in both Normal and Max Power modes.
void apply_wifi_power_settings(void);

// Shared scan results (from wifi_scanner, used by attacks/sniffer)
extern wifi_ap_record_t g_shared_scan_results[MAX_SCAN_RESULTS];
extern uint16_t g_shared_scan_count;
extern int g_shared_selected_indices[MAX_SCAN_RESULTS];
extern int g_shared_selected_count;

// Helper macros
#include "esp_log.h"
#define MY_LOG_INFO(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)

// Common helper functions
const char* authmode_to_string(wifi_auth_mode_t mode);
void escape_csv_field(const char* input, char* output, size_t output_size);
bool is_multicast_mac(const uint8_t *mac);
bool is_broadcast_bssid(const uint8_t *bssid);
bool is_own_device_mac(const uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif // WIFI_COMMON_H

