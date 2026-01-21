#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include "wifi_common.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// SNIFFER API
// ============================================================================

/**
 * @brief Start WiFi sniffer (promiscuous mode)
 */
esp_err_t wifi_sniffer_start(void);

/**
 * @brief Stop WiFi sniffer
 */
esp_err_t wifi_sniffer_stop(void);

/**
 * @brief Check if sniffer is active
 */
bool wifi_sniffer_is_active(void);

/**
 * @brief Get number of sniffed APs
 */
int wifi_sniffer_get_ap_count(void);

/**
 * @brief Get number of sniffed probe requests
 */
int wifi_sniffer_get_probe_count(void);

/**
 * @brief Get total packet count
 */
uint32_t wifi_sniffer_get_packet_count(void);

/**
 * @brief Get sniffed APs data (read-only access)
 * @param count Output parameter for number of APs
 * @return Pointer to AP array or NULL if not available
 */
const sniffer_ap_t* wifi_sniffer_get_aps(int *count);

/**
 * @brief Get probe requests data (read-only access)
 * @param count Output parameter for number of probes
 * @return Pointer to probe array or NULL if not available
 */
const probe_request_t* wifi_sniffer_get_probes(int *count);

/**
 * @brief Show sniffed AP results
 */
void wifi_sniffer_show_results(void);

/**
 * @brief Show clients for specific AP
 * @param ap_index Index of AP in sniffed list
 */
void wifi_sniffer_show_clients(int ap_index);

/**
 * @brief Show all probe requests
 */
void wifi_sniffer_show_probes(void);

/**
 * @brief List probe requests (alias)
 */
void wifi_sniffer_list_probes(void);

/**
 * @brief Enable/disable debug output
 */
void wifi_sniffer_set_debug(bool enable);

// ============================================================================
// CHANNEL CONTROL API
// ============================================================================

/**
 * @brief Get current channel
 */
uint8_t wifi_sniffer_get_current_channel(void);

/**
 * @brief Pause channel hopping
 */
void wifi_sniffer_pause_channel_hop(void);

/**
 * @brief Resume channel hopping
 */
void wifi_sniffer_resume_channel_hop(void);

/**
 * @brief Set fixed channel (for observation mode)
 * @param channel WiFi channel to lock to
 */
void wifi_sniffer_set_fixed_channel(uint8_t channel);

/**
 * @brief Check if channel hopping is paused
 */
bool wifi_sniffer_is_channel_hop_paused(void);

// ============================================================================
// CALLBACK API
// ============================================================================

/**
 * @brief Callback type for new client detection
 */
typedef void (*sniffer_new_client_cb_t)(void);

/**
 * @brief Set callback for new client detection (for UI refresh)
 * @param cb Callback function, or NULL to disable
 */
void wifi_sniffer_set_new_client_callback(sniffer_new_client_cb_t cb);

// ============================================================================
// NOSCAN API
// ============================================================================

/**
 * @brief Start sniffer without resetting data (resume mode)
 * @return ESP_OK on success
 */
esp_err_t wifi_sniffer_start_noscan(void);

/**
 * @brief Clear all sniffer data (networks, clients, probes)
 * Call this for a fresh rescan
 */
void wifi_sniffer_clear_data(void);

// ============================================================================
// SNIFFER DOG API (Passive client detection)
// ============================================================================

/**
 * @brief Start SnifferDog (passive probe request detection)
 */
esp_err_t wifi_sniffer_dog_start(void);

/**
 * @brief Stop SnifferDog
 */
esp_err_t wifi_sniffer_dog_stop(void);

/**
 * @brief Check if SnifferDog is active
 */
bool wifi_sniffer_dog_is_active(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SNIFFER_H
