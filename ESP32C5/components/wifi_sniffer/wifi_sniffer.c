#include "wifi_sniffer.h"
#include "wifi_scanner.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "wifi_sniffer";

// Sniffer state - large buffers dynamically allocated in PSRAM to save internal RAM
static sniffer_ap_t *sniffer_aps = NULL;
static int sniffer_ap_count = 0;
static probe_request_t *probe_requests = NULL;
static int probe_request_count = 0;

static volatile bool sniffer_active = false;
static volatile bool sniffer_scan_phase = false;
static volatile bool sniffer_selected_mode = false;
static volatile bool sniff_debug = false;
static uint32_t sniffer_packet_count = 0;

static uint8_t sniffer_current_channel = 1;
static int sniffer_channel_index = 0;
static uint32_t sniffer_last_channel_hop = 0;
static TaskHandle_t sniffer_channel_task_handle = NULL;

// Channel hop control
static volatile bool sniffer_channel_hop_paused = false;

// New client callback for UI refresh
static sniffer_new_client_cb_t sniffer_new_client_cb = NULL;

// Channel list for hopping (2.4GHz + 5GHz)
static const uint8_t channel_list[] = {
    // 2.4 GHz (1-13)
    1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13,
    // 5 GHz UNII-1 (36-48)
    36, 40, 44, 48,
    // 5 GHz UNII-2A (52-64)
    52, 56, 60, 64,
    // 5 GHz UNII-2C (100-144)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    // 5 GHz UNII-3 (149-165)
    149, 153, 157, 161, 165
};
static const int channel_list_size = sizeof(channel_list) / sizeof(channel_list[0]);

// Selected networks mode - channels to hop on
static uint8_t sniffer_selected_channels[MAX_AP_CNT];
static int sniffer_selected_channels_count = 0;

// Forward declarations
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void sniffer_channel_hop_task(void *pvParameters);
static void sniffer_process_scan_results(void);
static void sniffer_init_selected_networks(void);

// Find or add AP in sniffer list
static sniffer_ap_t* find_or_add_ap(const uint8_t *bssid) {
    if (sniffer_aps == NULL) return NULL;
    
    // Find existing
    for (int i = 0; i < sniffer_ap_count; i++) {
        if (memcmp(sniffer_aps[i].bssid, bssid, 6) == 0) {
            sniffer_aps[i].last_seen = esp_timer_get_time() / 1000;
            return &sniffer_aps[i];
        }
    }
    
    // In selected mode, don't add new APs - only track selected ones
    if (sniffer_selected_mode) {
        return NULL;
    }
    
    // Add new (only in normal/scan-all mode)
    if (sniffer_ap_count < MAX_SNIFFER_APS) {
        sniffer_ap_t *ap = &sniffer_aps[sniffer_ap_count];
        memcpy(ap->bssid, bssid, 6);
        ap->last_seen = esp_timer_get_time() / 1000;
        ap->client_count = 0;
        ap->ssid[0] = '\0';
        ap->rssi = -100;
        sniffer_ap_count++;
        return ap;
    }
    
    return NULL;
}

// Add client to AP
static void add_client_to_sniffer_ap(sniffer_ap_t *ap, const uint8_t *mac, int8_t rssi) {
    if (!ap) return;
    
    // Check if client already exists
    for (int i = 0; i < ap->client_count; i++) {
        if (memcmp(ap->clients[i].mac, mac, 6) == 0) {
            ap->clients[i].last_seen = esp_timer_get_time() / 1000;
            ap->clients[i].rssi = rssi;
            return;
        }
    }
    
    // Add new client
    if (ap->client_count < MAX_CLIENTS_PER_AP) {
        memcpy(ap->clients[ap->client_count].mac, mac, 6);
        ap->clients[ap->client_count].last_seen = esp_timer_get_time() / 1000;
        ap->clients[ap->client_count].rssi = rssi;
        ap->client_count++;
        
        // Notify UI about new client
        if (sniffer_new_client_cb) {
            sniffer_new_client_cb();
        }
    }
}

// Add probe request
static void add_probe_request(const uint8_t *sta_mac, const char *ssid, int8_t rssi) {
    if (probe_requests == NULL) return;
    
    // Check if already exists (update)
    for (int i = 0; i < probe_request_count; i++) {
        if (memcmp(probe_requests[i].mac, sta_mac, 6) == 0 &&
            strcmp(probe_requests[i].ssid, ssid) == 0) {
            probe_requests[i].last_seen = esp_timer_get_time() / 1000;
            probe_requests[i].rssi = rssi;
            return;
        }
    }
    
    // Add new
    if (probe_request_count < MAX_PROBE_REQUESTS) {
        memcpy(probe_requests[probe_request_count].mac, sta_mac, 6);
        strncpy(probe_requests[probe_request_count].ssid, ssid, 32);
        probe_requests[probe_request_count].ssid[32] = '\0';
        probe_requests[probe_request_count].last_seen = esp_timer_get_time() / 1000;
        probe_requests[probe_request_count].rssi = rssi;
        probe_request_count++;
    }
}

// WiFi promiscuous packet handler
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    if (!sniffer_active) return;
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *frame = ppkt->payload;
    const uint16_t frame_len = ppkt->rx_ctrl.sig_len;
    
    if (frame_len < 24) return; // Too short
    
    // Increment packet counter and log every 50 packets
    sniffer_packet_count++;
    if (sniffer_packet_count % 50 == 0) {
        ESP_LOGI(TAG, "[Sniffer] %lu packets processed | APs: %d | Probes: %d",
                 (unsigned long)sniffer_packet_count, sniffer_ap_count, probe_request_count);
    }
    
    // Frame Control Field
    uint16_t fc = (frame[1] << 8) | frame[0];
    uint8_t frame_type = (fc & 0x0C) >> 2;
    uint8_t frame_subtype = (fc & 0xF0) >> 4;
    
    int8_t rssi = ppkt->rx_ctrl.rssi;
    
    // Management frames (type 0)
    if (frame_type == 0) {
        // Beacon (subtype 8)
        if (frame_subtype == 8 && frame_len >= 36) {
            uint8_t *bssid = (uint8_t *)&frame[10];
            
            if (is_broadcast_bssid(bssid) || is_multicast_mac(bssid)) {
                return;
            }
            
            sniffer_ap_t *ap = find_or_add_ap(bssid);
            if (ap) {
                ap->channel = ppkt->rx_ctrl.channel;
                ap->rssi = rssi;
                
                // Extract SSID from beacon
                uint8_t *body = (uint8_t *)&frame[36];
                int body_len = frame_len - 36;
                
                if (body_len > 2 && body[0] == 0) { // SSID element
                    uint8_t ssid_len = body[1];
                    if (ssid_len <= 32 && body_len >= (2 + ssid_len)) {
                        memcpy(ap->ssid, &body[2], ssid_len);
                        ap->ssid[ssid_len] = '\0';
                    }
                }
            }
        }
        // Probe Request (subtype 4)
        else if (frame_subtype == 4 && frame_len >= 24) {
            uint8_t *sta_mac = (uint8_t *)&frame[10];
            
            if (is_multicast_mac(sta_mac) || is_own_device_mac(sta_mac)) {
                return;
            }
            
            // Extract SSID
            if (frame_len >= 26) {
                uint8_t *body = (uint8_t *)&frame[24];
                int body_len = frame_len - 24;
                
                if (body_len > 2 && body[0] == 0) { // SSID element
                    uint8_t ssid_len = body[1];
                    if (ssid_len > 0 && ssid_len <= 32 && body_len >= (2 + ssid_len)) {
                        char ssid[33];
                        memcpy(ssid, &body[2], ssid_len);
                        ssid[ssid_len] = '\0';
                        
                        add_probe_request(sta_mac, ssid, rssi);
                        
                        if (sniff_debug) {
                            ESP_LOGI("sniffer", "[PROBE] %02X:%02X:%02X:%02X:%02X:%02X -> %s (RSSI: %d)",
                                   sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
                                   ssid, rssi);
                        }
                    }
                }
            }
        }
    }
    // Data frames (type 2)
    else if (frame_type == 2 && frame_len >= 24) {
        uint8_t to_ds = (fc & 0x0100) >> 8;
        uint8_t from_ds = (fc & 0x0200) >> 9;
        
        uint8_t *addr1 = (uint8_t *)&frame[4];
        uint8_t *addr2 = (uint8_t *)&frame[10];
        uint8_t *addr3 = (uint8_t *)&frame[16];
        
        uint8_t *bssid = NULL;
        uint8_t *sta_mac = NULL;
        
        // Determine BSSID and STA based on To/From DS
        if (to_ds == 0 && from_ds == 0) {
            bssid = addr3;
            sta_mac = addr2;
        } else if (to_ds == 1 && from_ds == 0) {
            bssid = addr1;
            sta_mac = addr2;
        } else if (to_ds == 0 && from_ds == 1) {
            bssid = addr2;
            sta_mac = addr1;
        } else {
            return; // WDS, ignore
        }
        
        if (is_broadcast_bssid(bssid) || is_multicast_mac(bssid) ||
            is_multicast_mac(sta_mac) || is_own_device_mac(sta_mac)) {
            return;
        }
        
        sniffer_ap_t *ap = find_or_add_ap(bssid);
        if (ap) {
            add_client_to_sniffer_ap(ap, sta_mac, rssi);
        }
    }
}

// Channel hopping task
static void sniffer_channel_hop_task(void *pvParameters) {
    ESP_LOGI(TAG, "Channel hop task started");
    
    while (sniffer_active) {
        // Check if channel hopping is paused (observation mode)
        if (sniffer_channel_hop_paused) {
            vTaskDelay(pdMS_TO_TICKS(100)); // Wait while paused
            continue;
        }
        
        // Use selected channels if in selected mode, otherwise use all channels
        if (sniffer_selected_mode && sniffer_selected_channels_count > 0) {
            sniffer_current_channel = sniffer_selected_channels[sniffer_channel_index];
            sniffer_channel_index = (sniffer_channel_index + 1) % sniffer_selected_channels_count;
        } else {
            sniffer_current_channel = channel_list[sniffer_channel_index];
            sniffer_channel_index = (sniffer_channel_index + 1) % channel_list_size;
        }
        
        esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(50);
        
        if (sniff_debug) {
            ESP_LOGI(TAG, "Hopped to channel %d", sniffer_current_channel);
        }
        
        sniffer_last_channel_hop = esp_timer_get_time() / 1000;
        
        vTaskDelay(pdMS_TO_TICKS(500)); // 500ms per channel
    }
    
    ESP_LOGI(TAG, "Channel hop task stopped");
    sniffer_channel_task_handle = NULL;
    vTaskDelete(NULL);
}

// Process scan results for normal mode
static void sniffer_process_scan_results(void) {
    if (g_shared_scan_count == 0) {
        return;
    }
    
    ESP_LOGI(TAG, "Processing %u scan results for sniffer...", g_shared_scan_count);
    
    // Clear existing sniffer data
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    
    // Copy scan results to sniffer structure
    for (int i = 0; i < g_shared_scan_count && i < MAX_SNIFFER_APS; i++) {
        wifi_ap_record_t *scan_ap = &g_shared_scan_results[i];
        sniffer_ap_t *sniffer_ap = &sniffer_aps[sniffer_ap_count++];
        
        memcpy(sniffer_ap->bssid, scan_ap->bssid, 6);
        strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
        sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
        sniffer_ap->channel = scan_ap->primary;
        sniffer_ap->authmode = scan_ap->authmode;
        sniffer_ap->rssi = scan_ap->rssi;
        sniffer_ap->client_count = 0;
        sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
    }
    
    ESP_LOGI(TAG, "Initialized %d APs for sniffer monitoring", sniffer_ap_count);
}

// Initialize sniffer with selected networks only
static void sniffer_init_selected_networks(void) {
    if (g_shared_selected_count == 0) {
        ESP_LOGI(TAG, "Cannot initialize selected networks - no selection");
        return;
    }
    
    ESP_LOGI(TAG, "Initializing sniffer for %d selected networks...", g_shared_selected_count);
    
    // Clear existing sniffer data
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    
    // Clear channel list
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    
    // Copy selected networks to sniffer structure
    for (int i = 0; i < g_shared_selected_count && sniffer_ap_count < MAX_SNIFFER_APS; i++) {
        int idx = g_shared_selected_indices[i];
        
        if (idx < 0 || idx >= (int)g_shared_scan_count) {
            ESP_LOGI(TAG, "Warning: Invalid selected index %d, skipping", idx);
            continue;
        }
        
        wifi_ap_record_t *scan_ap = &g_shared_scan_results[idx];
        sniffer_ap_t *sniffer_ap = &sniffer_aps[sniffer_ap_count++];
        
        memcpy(sniffer_ap->bssid, scan_ap->bssid, 6);
        strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
        sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
        sniffer_ap->channel = scan_ap->primary;
        sniffer_ap->authmode = scan_ap->authmode;
        sniffer_ap->rssi = scan_ap->rssi;
        sniffer_ap->client_count = 0;
        sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
        
        // Add channel to unique channel list
        bool channel_exists = false;
        for (int j = 0; j < sniffer_selected_channels_count; j++) {
            if (sniffer_selected_channels[j] == scan_ap->primary) {
                channel_exists = true;
                break;
            }
        }
        
        if (!channel_exists && sniffer_selected_channels_count < MAX_AP_CNT) {
            sniffer_selected_channels[sniffer_selected_channels_count++] = scan_ap->primary;
        }
        
        ESP_LOGI(TAG, "  [%d] SSID='%s' Ch=%d BSSID=%02x:%02x:%02x:%02x:%02x:%02x", 
                   i + 1, sniffer_ap->ssid, sniffer_ap->channel,
                   sniffer_ap->bssid[0], sniffer_ap->bssid[1], sniffer_ap->bssid[2],
                   sniffer_ap->bssid[3], sniffer_ap->bssid[4], sniffer_ap->bssid[5]);
    }
    
    ESP_LOGI(TAG, "Sniffer initialized: %d networks on %d unique channel(s)", 
               sniffer_ap_count, sniffer_selected_channels_count);
    
    // Log channels
    if (sniffer_selected_channels_count > 0) {
        char channel_list_str[128] = {0};
        int offset = 0;
        for (int i = 0; i < sniffer_selected_channels_count && offset < 120; i++) {
            offset += snprintf(channel_list_str + offset, sizeof(channel_list_str) - offset, 
                             "%d%s", sniffer_selected_channels[i], 
                             (i < sniffer_selected_channels_count - 1) ? ", " : "");
        }
        ESP_LOGI(TAG, "Channel hopping list: [%s]", channel_list_str);
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

esp_err_t wifi_sniffer_start(void) {
    if (sniffer_active) {
        ESP_LOGW(TAG, "Sniffer already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    // Allocate buffers in PSRAM if not already allocated
    if (sniffer_aps == NULL) {
        sniffer_aps = (sniffer_ap_t *)heap_caps_calloc(MAX_SNIFFER_APS, sizeof(sniffer_ap_t), MALLOC_CAP_SPIRAM);
        if (sniffer_aps == NULL) {
            ESP_LOGE(TAG, "Failed to allocate sniffer_aps in PSRAM");
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "Allocated %d bytes for sniffer_aps in PSRAM", MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    }
    
    if (probe_requests == NULL) {
        probe_requests = (probe_request_t *)heap_caps_calloc(MAX_PROBE_REQUESTS, sizeof(probe_request_t), MALLOC_CAP_SPIRAM);
        if (probe_requests == NULL) {
            ESP_LOGE(TAG, "Failed to allocate probe_requests in PSRAM");
            heap_caps_free(sniffer_aps);
            sniffer_aps = NULL;
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "Allocated %d bytes for probe_requests in PSRAM", MAX_PROBE_REQUESTS * sizeof(probe_request_t));
    }
    
    // Clear previous data
    sniffer_ap_count = 0;
    probe_request_count = 0;
    sniffer_packet_count = 0;
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    
    // Check if networks were selected
    if (g_shared_selected_count > 0) {
        // Selected networks mode - skip scan, use selected networks only
        ESP_LOGI(TAG, "[Sniffer] Starting in SELECTED NETWORKS mode...");
        ESP_LOGI(TAG, "[Sniffer] Will monitor %d pre-selected network(s)", g_shared_selected_count);
        
        sniffer_active = true;
        sniffer_scan_phase = false; // Skip scan phase
        sniffer_selected_mode = true;
        
        // Initialize sniffer with selected networks
        sniffer_init_selected_networks();
        
        if (sniffer_ap_count == 0 || sniffer_selected_channels_count == 0) {
            ESP_LOGI(TAG, "Failed to initialize selected networks for sniffer");
            sniffer_active = false;
            sniffer_selected_mode = false;
            return ESP_FAIL;
        }
        
        // Set promiscuous mode
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
        
        // Initialize channel hopping with selected channels
        sniffer_channel_index = 0;
        sniffer_current_channel = sniffer_selected_channels[0];
        sniffer_last_channel_hop = esp_timer_get_time() / 1000;
        esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
        
        // Start channel hopping task
        xTaskCreate(sniffer_channel_hop_task, "sniffer_ch_hop", 4096, NULL, 5, &sniffer_channel_task_handle);
        
        ESP_LOGI(TAG, "[Sniffer] Now monitoring selected networks (no scan performed)");
        
    } else {
        // Normal mode - needs external scan management
        // This mode requires the caller to handle scanning via wifi_scanner
        ESP_LOGI(TAG, "[Sniffer] Starting in NORMAL mode (scan all networks)...");
        
        sniffer_active = true;
        sniffer_scan_phase = true; // Caller should trigger scan
        sniffer_selected_mode = false;
        
        // Note: In normal mode, caller must:
        // 1. Call wifi_scanner to scan networks
        // 2. After scan completes, call sniffer_process_scan_results() (if exposed) or
        //    handle scan results and then enable promiscuous mode
        // For now, we'll just start promiscuous mode immediately
        
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
        
        sniffer_active = true;
        sniffer_channel_index = 0;
        
        // Start channel hopping task
        xTaskCreate(sniffer_channel_hop_task, "sniffer_ch_hop", 16384, NULL, 5, &sniffer_channel_task_handle);
        
        ESP_LOGI(TAG, "[Sniffer] Started - monitoring packets...");
    }
    
    return ESP_OK;
}

esp_err_t wifi_sniffer_stop(void) {
    if (!sniffer_active) {
        ESP_LOGW(TAG, "Sniffer not running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Stopping sniffer...");
    
    sniffer_active = false;
    sniffer_channel_hop_paused = false;
    
    // Wait for task to finish
    int wait_count = 0;
    while (sniffer_channel_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    esp_wifi_set_promiscuous(false);
    
    ESP_LOGI(TAG, "[Sniffer] Stopped | Total packets: %lu | APs: %d | Probes: %d", 
             (unsigned long)sniffer_packet_count, sniffer_ap_count, probe_request_count);
    
    // Reset mode flags
    sniffer_scan_phase = false;
    sniffer_selected_mode = false;
    
    // NOTE: Do NOT free PSRAM buffers - preserve data for noscan restart
    // Data will be preserved until explicitly cleared or process restart
    
    return ESP_OK;
}

bool wifi_sniffer_is_active(void) {
    return sniffer_active;
}

int wifi_sniffer_get_ap_count(void) {
    return sniffer_ap_count;
}

int wifi_sniffer_get_probe_count(void) {
    return probe_request_count;
}

uint32_t wifi_sniffer_get_packet_count(void) {
    return sniffer_packet_count;
}

const sniffer_ap_t* wifi_sniffer_get_aps(int *count) {
    if (count) {
        *count = sniffer_ap_count;
    }
    return sniffer_aps;
}

const probe_request_t* wifi_sniffer_get_probes(int *count) {
    if (count) {
        *count = probe_request_count;
    }
    return probe_requests;
}

void wifi_sniffer_show_results(void) {
    if (sniffer_aps == NULL) {
        ESP_LOGW(TAG, "Sniffer not initialized");
        return;
    }
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Sniffed APs ===");
    ESP_LOGI(TAG, "BSSID,SSID,Channel,RSSI,Clients");
    
    for (int i = 0; i < sniffer_ap_count; i++) {
        sniffer_ap_t *ap = &sniffer_aps[i];
        
        ESP_LOGI("sniffer", "%02X:%02X:%02X:%02X:%02X:%02X,",
               ap->bssid[0], ap->bssid[1], ap->bssid[2],
               ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        
        if (ap->ssid[0] != '\0') {
            char ssid_escaped[128];
            escape_csv_field((const char *)ap->ssid, ssid_escaped, sizeof(ssid_escaped));
            ESP_LOGI("sniffer", "%s,", ssid_escaped);
        } else {
            ESP_LOGI("sniffer", "<hidden>,");
        }
        
        ESP_LOGI("sniffer", "%d,%d,%d", ap->channel, ap->rssi, ap->client_count);
    }
    
    ESP_LOGI(TAG, "Total APs: %d", sniffer_ap_count);
}

void wifi_sniffer_show_clients(int ap_index) {
    if (sniffer_aps == NULL) {
        ESP_LOGW(TAG, "Sniffer not initialized");
        return;
    }
    
    if (ap_index < 0 || ap_index >= sniffer_ap_count) {
        ESP_LOGE(TAG, "Invalid AP index");
        return;
    }
    
    sniffer_ap_t *ap = &sniffer_aps[ap_index];
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Clients for AP %02X:%02X:%02X:%02X:%02X:%02X ===",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    ESP_LOGI(TAG, "MAC,RSSI,Last Seen");
    
    for (int i = 0; i < ap->client_count; i++) {
        client_info_t *client = &ap->clients[i];
        ESP_LOGI("sniffer", "%02X:%02X:%02X:%02X:%02X:%02X,%d,%lu",
               client->mac[0], client->mac[1], client->mac[2],
               client->mac[3], client->mac[4], client->mac[5],
               client->rssi, (unsigned long)client->last_seen);
    }
    
    ESP_LOGI(TAG, "Total clients: %d", ap->client_count);
}

void wifi_sniffer_show_probes(void) {
    if (probe_requests == NULL) {
        ESP_LOGW(TAG, "Sniffer not initialized");
        return;
    }
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Probe Requests ===");
    ESP_LOGI(TAG, "STA MAC,SSID,RSSI,Last Seen");
    
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        
        char ssid_escaped[128];
        escape_csv_field(probe->ssid, ssid_escaped, sizeof(ssid_escaped));
        
        ESP_LOGI("sniffer", "%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,%lu",
               probe->mac[0], probe->mac[1], probe->mac[2],
               probe->mac[3], probe->mac[4], probe->mac[5],
               ssid_escaped, probe->rssi, (unsigned long)probe->last_seen);
    }
    
    ESP_LOGI(TAG, "Total probe requests: %d", probe_request_count);
}

void wifi_sniffer_list_probes(void) {
    wifi_sniffer_show_probes();
}

void wifi_sniffer_set_debug(bool enable) {
    sniff_debug = enable;
    ESP_LOGI(TAG, "Sniffer debug %s", enable ? "enabled" : "disabled");
}

// ============================================================================
// CHANNEL CONTROL API
// ============================================================================

uint8_t wifi_sniffer_get_current_channel(void) {
    return sniffer_current_channel;
}

void wifi_sniffer_pause_channel_hop(void) {
    sniffer_channel_hop_paused = true;
    ESP_LOGI(TAG, "Channel hopping paused");
}

void wifi_sniffer_resume_channel_hop(void) {
    sniffer_channel_hop_paused = false;
    ESP_LOGI(TAG, "Channel hopping resumed");
}

void wifi_sniffer_set_fixed_channel(uint8_t channel) {
    sniffer_channel_hop_paused = true;
    sniffer_current_channel = channel;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI(TAG, "Fixed channel set to %d", channel);
}

bool wifi_sniffer_is_channel_hop_paused(void) {
    return sniffer_channel_hop_paused;
}

// ============================================================================
// CALLBACK API
// ============================================================================

void wifi_sniffer_set_new_client_callback(sniffer_new_client_cb_t cb) {
    sniffer_new_client_cb = cb;
    ESP_LOGI(TAG, "New client callback %s", cb ? "set" : "cleared");
}

// ============================================================================
// NOSCAN API
// ============================================================================

esp_err_t wifi_sniffer_start_noscan(void) {
    if (sniffer_active) {
        ESP_LOGW(TAG, "Sniffer already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Starting sniffer without reset (noscan mode)...");
    
    // Allocate buffers in PSRAM if not already allocated
    if (sniffer_aps == NULL) {
        sniffer_aps = (sniffer_ap_t *)heap_caps_calloc(MAX_SNIFFER_APS, sizeof(sniffer_ap_t), MALLOC_CAP_SPIRAM);
        if (sniffer_aps == NULL) {
            ESP_LOGE(TAG, "Failed to allocate sniffer_aps in PSRAM");
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "Allocated %d bytes for sniffer_aps in PSRAM", MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    }
    
    if (probe_requests == NULL) {
        probe_requests = (probe_request_t *)heap_caps_calloc(MAX_PROBE_REQUESTS, sizeof(probe_request_t), MALLOC_CAP_SPIRAM);
        if (probe_requests == NULL) {
            ESP_LOGE(TAG, "Failed to allocate probe_requests in PSRAM");
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "Allocated %d bytes for probe_requests in PSRAM", MAX_PROBE_REQUESTS * sizeof(probe_request_t));
    }
    
    // NOTE: Do NOT clear sniffer_ap_count or probe_request_count - preserve existing data
    
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    sniffer_channel_hop_paused = false;
    
    // Normal mode - don't reset data
    sniffer_active = true;
    sniffer_scan_phase = false;
    sniffer_selected_mode = false;
    
    // Set promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    
    sniffer_channel_index = 0;
    sniffer_current_channel = channel_list[0];
    esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
    
    // Start channel hopping task
    if (sniffer_channel_task_handle == NULL) {
        xTaskCreate(sniffer_channel_hop_task, "sniffer_ch_hop", 8192, NULL, 5, &sniffer_channel_task_handle);
    }
    
    ESP_LOGI(TAG, "[Sniffer] Started in noscan mode - preserved %d APs, %d probes", 
             sniffer_ap_count, probe_request_count);
    
    return ESP_OK;
}

void wifi_sniffer_clear_data(void) {
    ESP_LOGI(TAG, "Clearing all sniffer data...");
    
    // Clear AP data
    sniffer_ap_count = 0;
    if (sniffer_aps != NULL) {
        memset(sniffer_aps, 0, MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    }
    
    // Clear probe data
    probe_request_count = 0;
    if (probe_requests != NULL) {
        memset(probe_requests, 0, MAX_PROBE_REQUESTS * sizeof(probe_request_t));
    }
    
    // Reset packet counter
    sniffer_packet_count = 0;
    
    ESP_LOGI(TAG, "Sniffer data cleared - ready for fresh scan");
}

// ============================================================================
// SNIFFER DOG (Passive client detection)
// ============================================================================

static volatile bool sniffer_dog_active = false;
static TaskHandle_t sniffer_dog_task_handle = NULL;
static uint8_t sniffer_dog_current_channel = 1;
static int sniffer_dog_channel_index = 0;
static uint32_t sniffer_dog_last_channel_hop = 0;

static void sniffer_dog_channel_hop_task(void *pvParameters) {
    ESP_LOGI(TAG, "SnifferDog channel hop task started");
    
    while (sniffer_dog_active) {
        sniffer_dog_current_channel = channel_list[sniffer_dog_channel_index];
        esp_wifi_set_channel(sniffer_dog_current_channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(50);
        sniffer_dog_channel_index = (sniffer_dog_channel_index + 1) % channel_list_size;
        sniffer_dog_last_channel_hop = esp_timer_get_time() / 1000;
        
        vTaskDelay(pdMS_TO_TICKS(300)); // 300ms per channel
    }
    
    ESP_LOGI(TAG, "SnifferDog channel hop task stopped");
    sniffer_dog_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_sniffer_dog_start(void) {
    if (sniffer_dog_active) {
        ESP_LOGW(TAG, "SnifferDog already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Starting SnifferDog...");
    
    // Allocate probe_requests buffer in PSRAM if not already allocated
    if (probe_requests == NULL) {
        probe_requests = (probe_request_t *)heap_caps_calloc(MAX_PROBE_REQUESTS, sizeof(probe_request_t), MALLOC_CAP_SPIRAM);
        if (probe_requests == NULL) {
            ESP_LOGE(TAG, "Failed to allocate probe_requests in PSRAM");
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "Allocated %d bytes for probe_requests in PSRAM", MAX_PROBE_REQUESTS * sizeof(probe_request_t));
    }
    
    // Clear previous data
    probe_request_count = 0;
    
    // Set promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    
    sniffer_dog_active = true;
    sniffer_dog_channel_index = 0;
    
    // Start channel hopping task
    xTaskCreate(sniffer_dog_channel_hop_task, "sniff_dog_ch", 16384, NULL, 5, &sniffer_dog_task_handle);
    
    ESP_LOGI(TAG, "SnifferDog started");
    return ESP_OK;
}

esp_err_t wifi_sniffer_dog_stop(void) {
    if (!sniffer_dog_active) {
        ESP_LOGW(TAG, "SnifferDog not running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Stopping SnifferDog...");
    
    sniffer_dog_active = false;
    
    // Wait for task to finish
    int wait_count = 0;
    while (sniffer_dog_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    esp_wifi_set_promiscuous(false);
    
    ESP_LOGI(TAG, "SnifferDog stopped. Probes: %d", probe_request_count);
    return ESP_OK;
}

bool wifi_sniffer_dog_is_active(void) {
    return sniffer_dog_active;
}
