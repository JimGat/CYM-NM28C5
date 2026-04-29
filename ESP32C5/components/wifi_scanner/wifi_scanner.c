// wifi_scanner.c - WiFi Network Scanner
#include "wifi_scanner.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include <string.h>

static const char *TAG = "wifi_scanner";

// Scanner state (local)
static volatile bool g_scan_in_progress = false;
static volatile bool g_scan_done = false;

// Shared scan results (defined in wifi_common.c, used by other components)
wifi_ap_record_t g_shared_scan_results[MAX_SCAN_RESULTS];
uint16_t g_shared_scan_count = 0;
int g_shared_selected_indices[MAX_SCAN_RESULTS];
int g_shared_selected_count = 0;

// Target BSSID monitoring (for deauth attacks)
static target_bssid_t target_bssids[MAX_TARGET_BSSIDS];
static int target_bssid_count = 0;

// Configurable active scan time per channel (set via wifi_scanner_set_scan_time)
static uint16_t g_scan_time_min = 100;  // default
static uint16_t g_scan_time_max = 300;  // default

// WiFi event handler (for scan completion)
static void wifi_scanner_event_handler(void *arg, esp_event_base_t event_base,
                                      int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE) {
        g_scan_in_progress = false;
        g_scan_done = true;
        ESP_LOGI(TAG, "Scan done");
        
        uint16_t number = MAX_SCAN_RESULTS;
        esp_wifi_scan_get_ap_num(&number);
        g_shared_scan_count = (number > MAX_SCAN_RESULTS) ? MAX_SCAN_RESULTS : number;
        
        if (g_shared_scan_count > 0) {
            esp_wifi_scan_get_ap_records(&g_shared_scan_count, g_shared_scan_results);
        }
    }
}

esp_err_t wifi_scanner_init(void) {
    // Register event handler for scan completion
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE,
                               &wifi_scanner_event_handler, NULL);
    return ESP_OK;
}

esp_err_t wifi_scanner_start_scan(void) {
    if (g_scan_in_progress) {
        ESP_LOGW(TAG, "Scan already in progress");
        return ESP_ERR_INVALID_STATE;
    }
    
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = g_scan_time_min,
        .scan_time.active.max = g_scan_time_max,
    };
    
    g_scan_in_progress = true;
    g_scan_done = false;
    g_shared_scan_count = 0;
    
    ESP_LOGI(TAG, "Starting WiFi scan...");
    esp_err_t ret = esp_wifi_scan_start(&scan_cfg, false);
    
    if (ret != ESP_OK) {
        g_scan_in_progress = false;
        ESP_LOGE(TAG, "Failed to start scan: %s", esp_err_to_name(ret));
        return ret;
    }
    
    return ESP_OK;
}

int wifi_scanner_get_results(wifi_ap_record_t *results, uint16_t max_results) {
    if (!results) return 0;
    
    uint16_t count = (g_shared_scan_count > max_results) ? max_results : g_shared_scan_count;
    memcpy(results, g_shared_scan_results, count * sizeof(wifi_ap_record_t));
    
    return count;
}

uint16_t wifi_scanner_get_count(void) {
    return g_shared_scan_count;
}

bool wifi_scanner_is_scanning(void) {
    return g_scan_in_progress;
}

bool wifi_scanner_is_done(void) {
    return g_scan_done;
}

void wifi_scanner_abort(void) {
    if (g_scan_in_progress) {
        esp_wifi_scan_stop();
        g_scan_in_progress = false;
    }
    g_scan_done = false;
}

esp_err_t wifi_scanner_select_network(int index, bool selected) {
    if (index < 0 || index >= g_shared_scan_count) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (selected) {
        // Add to selection
        bool already_selected = false;
        for (int i = 0; i < g_shared_selected_count; i++) {
            if (g_shared_selected_indices[i] == index) {
                already_selected = true;
                break;
            }
        }
        
        if (!already_selected && g_shared_selected_count < MAX_SCAN_RESULTS) {
            g_shared_selected_indices[g_shared_selected_count++] = index;
        }
    } else {
        // Remove from selection
        for (int i = 0; i < g_shared_selected_count; i++) {
            if (g_shared_selected_indices[i] == index) {
                for (int j = i; j < g_shared_selected_count - 1; j++) {
                    g_shared_selected_indices[j] = g_shared_selected_indices[j + 1];
                }
                g_shared_selected_count--;
                break;
            }
        }
    }
    
    return ESP_OK;
}

int wifi_scanner_get_selected(int *indices, int max_indices) {
    if (!indices) return 0;
    
    int count = (g_shared_selected_count > max_indices) ? max_indices : g_shared_selected_count;
    memcpy(indices, g_shared_selected_indices, count * sizeof(int));
    
    return count;
}

int wifi_scanner_get_selected_count(void) {
    return g_shared_selected_count;
}

void wifi_scanner_print_results(void) {
    if (g_shared_scan_count == 0) {
        MY_LOG_INFO(TAG, "No networks found");
        return;
    }
    
    MY_LOG_INFO(TAG, "");
    MY_LOG_INFO(TAG, "Index,BSSID,SSID,Auth,Channel,RSSI");
    
    for (int i = 0; i < g_shared_scan_count; i++) {
        wifi_ap_record_t *ap = &g_shared_scan_results[i];
        
        char ssid_escaped[128];
        escape_csv_field((const char*)ap->ssid, ssid_escaped, sizeof(ssid_escaped));
        
        ESP_LOGI("scanner", "%d,%02X:%02X:%02X:%02X:%02X:%02X,%s,%s,%d,%d",
               i,
               ap->bssid[0], ap->bssid[1], ap->bssid[2],
               ap->bssid[3], ap->bssid[4], ap->bssid[5],
               ssid_escaped,
               authmode_to_string(ap->authmode),
               ap->primary,
               ap->rssi);
    }
    
    MY_LOG_INFO(TAG, "Total networks: %d", g_shared_scan_count);
}

// Save selected network BSSIDs to target list
void wifi_scanner_save_target_bssids(void) {
    target_bssid_count = 0;
    
    for (int i = 0; i < g_shared_selected_count && target_bssid_count < MAX_TARGET_BSSIDS; i++) {
        int idx = g_shared_selected_indices[i];
        if (idx >= 0 && idx < g_shared_scan_count) {
            memcpy(target_bssids[target_bssid_count].bssid, 
                   g_shared_scan_results[idx].bssid, 6);
            // Copy SSID
            strncpy(target_bssids[target_bssid_count].ssid, 
                   (const char *)g_shared_scan_results[idx].ssid, 32);
            target_bssids[target_bssid_count].ssid[32] = '\0';
            target_bssids[target_bssid_count].channel = g_shared_scan_results[idx].primary;
            target_bssids[target_bssid_count].last_seen = esp_timer_get_time() / 1000;
            target_bssids[target_bssid_count].active = true;
            target_bssid_count++;
        }
    }
    
    ESP_LOGI(TAG, "Saved %d target BSSIDs", target_bssid_count);
}

// Get target BSSID list
int wifi_scanner_get_targets(target_bssid_t *targets, int max_targets) {
    if (!targets) return 0;
    
    int count = (target_bssid_count > max_targets) ? max_targets : target_bssid_count;
    memcpy(targets, target_bssids, count * sizeof(target_bssid_t));
    
    return count;
}

int wifi_scanner_get_target_count(void) {
    return target_bssid_count;
}

// Quick channel scan for specific targets
void wifi_scanner_quick_channel_scan(void) {
    if (target_bssid_count == 0) {
        ESP_LOGW(TAG, "No targets to scan");
        return;
    }
    
    // Check channels where targets were last seen
    for (int i = 0; i < target_bssid_count; i++) {
        if (!target_bssids[i].active) continue;
        
        uint8_t channel = target_bssids[i].channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Mark as seen (timestamp updated by sniffer callback)
        target_bssids[i].last_seen = esp_timer_get_time() / 1000;
    }
}

// Check if target is still active
bool wifi_scanner_is_target_active(const uint8_t *bssid) {
    for (int i = 0; i < target_bssid_count; i++) {
        if (memcmp(target_bssids[i].bssid, bssid, 6) == 0) {
            return target_bssids[i].active;
        }
    }
    return false;
}

// Update target last seen time
void wifi_scanner_update_target_seen(const uint8_t *bssid) {
    for (int i = 0; i < target_bssid_count; i++) {
        if (memcmp(target_bssids[i].bssid, bssid, 6) == 0) {
            target_bssids[i].last_seen = esp_timer_get_time() / 1000;
            target_bssids[i].active = true;
            break;
        }
    }
}

// Clear all targets
void wifi_scanner_clear_targets(void) {
    target_bssid_count = 0;
    ESP_LOGI(TAG, "Cleared all targets");
}

// Clear all network selections
void wifi_scanner_clear_selections(void) {
    g_shared_selected_count = 0;
    memset(g_shared_selected_indices, 0, sizeof(g_shared_selected_indices));
    ESP_LOGI(TAG, "Cleared all network selections");
}

const wifi_ap_record_t *wifi_scanner_get_results_ptr(void)
{
    return g_shared_scan_results;
}

const uint16_t *wifi_scanner_get_count_ptr(void)
{
    return &g_shared_scan_count;
}

void wifi_scanner_set_scan_time(uint16_t min_ms, uint16_t max_ms)
{
    if (min_ms < 50)  min_ms = 50;
    if (max_ms > 1000) max_ms = 1000;
    if (min_ms > max_ms) min_ms = max_ms;
    g_scan_time_min = min_ms;
    g_scan_time_max = max_ms;
    ESP_LOGI(TAG, "Scan time set: min=%u max=%u ms", min_ms, max_ms);
}

