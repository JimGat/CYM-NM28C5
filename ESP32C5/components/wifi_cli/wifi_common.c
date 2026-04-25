// wifi_common.c - Common helper functions
#include "wifi_common.h"
#include "esp_wifi.h"
#include <string.h>

// Global variables (defined once, extern in header)
led_strip_handle_t g_led_strip = NULL;
volatile app_state_t g_app_state = APP_STATE_IDLE;
volatile bool g_operation_stop_requested = false;
bool g_max_power_mode = false;  // default Normal; persisted in NVS by main.c

void apply_wifi_power_settings(void)
{
    if (g_max_power_mode) {
        // 82 is the highest TX power value accepted by the IDF API (~20.5 dBm nominal).
        // Actual radiated EIRP is still bounded by PHY calibration, antenna design, and
        // country/regulatory settings loaded at runtime.
        esp_wifi_set_max_tx_power(82);
        esp_wifi_set_ps(WIFI_PS_NONE);   // disable modem sleep for continuous TX capability
    } else {
        esp_wifi_set_ps(WIFI_PS_MIN_MODEM);  // restore default modem-sleep power save
    }
}

const char* authmode_to_string(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK: return "WAPI_PSK";
        default: return "Unknown";
    }
}

void escape_csv_field(const char* input, char* output, size_t output_size) {
    size_t i = 0, j = 0;
    bool needs_quotes = false;
    
    if (!input || !output || output_size < 3) return;
    
    for (i = 0; input[i] != '\0'; i++) {
        if (input[i] == ',' || input[i] == '"' || input[i] == '\n') {
            needs_quotes = true;
            break;
        }
    }
    
    if (needs_quotes) {
        output[j++] = '"';
        for (i = 0; input[i] != '\0' && j < output_size - 3; i++) {
            if (input[i] == '"') {
                output[j++] = '"';
                output[j++] = '"';
            } else {
                output[j++] = input[i];
            }
        }
        output[j++] = '"';
        output[j] = '\0';
    } else {
        strncpy(output, input, output_size - 1);
        output[output_size - 1] = '\0';
    }
}

bool is_multicast_mac(const uint8_t *mac) {
    return (mac[0] & 0x01) != 0;
}

bool is_broadcast_bssid(const uint8_t *bssid) {
    return (bssid[0] == 0xFF && bssid[1] == 0xFF && bssid[2] == 0xFF &&
            bssid[3] == 0xFF && bssid[4] == 0xFF && bssid[5] == 0xFF);
}

bool is_own_device_mac(const uint8_t *mac) {
    uint8_t own_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, own_mac);
    return memcmp(mac, own_mac, 6) == 0;
}
