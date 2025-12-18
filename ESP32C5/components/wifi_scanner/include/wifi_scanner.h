#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include "wifi_common.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// SCANNER API
// ============================================================================

/**
 * @brief Initialize WiFi scanner
 */
esp_err_t wifi_scanner_init(void);

/**
 * @brief Start background WiFi scan
 */
esp_err_t wifi_scanner_start_scan(void);

/**
 * @brief Get scan results
 * @param results Buffer to store results
 * @param max_results Maximum results to return
 * @return Number of results returned
 */
int wifi_scanner_get_results(wifi_ap_record_t *results, uint16_t max_results);
const wifi_ap_record_t *wifi_scanner_get_results_ptr(void);
const uint16_t *wifi_scanner_get_count_ptr(void);

/**
 * @brief Get scan count
 */
uint16_t wifi_scanner_get_count(void);

/**
 * @brief Check if scan is in progress
 */
bool wifi_scanner_is_scanning(void);

/**
 * @brief Check if scan is done
 */
bool wifi_scanner_is_done(void);

/**
 * @brief Select/deselect network by index
 */
esp_err_t wifi_scanner_select_network(int index, bool selected);

/**
 * @brief Get selected network indices
 */
int wifi_scanner_get_selected(int *indices, int max_indices);

/**
 * @brief Get selected network count
 */
int wifi_scanner_get_selected_count(void);

/**
 * @brief Print scan results to console
 */
void wifi_scanner_print_results(void);

/**
 * @brief Save selected networks to target BSSID list
 */
void wifi_scanner_save_target_bssids(void);

/**
 * @brief Get target BSSID list
 */
int wifi_scanner_get_targets(target_bssid_t *targets, int max_targets);

/**
 * @brief Get target BSSID count
 */
int wifi_scanner_get_target_count(void);

/**
 * @brief Perform quick scan of target channels
 */
void wifi_scanner_quick_channel_scan(void);

/**
 * @brief Check if target BSSID is active
 */
bool wifi_scanner_is_target_active(const uint8_t *bssid);

/**
 * @brief Update target last seen timestamp
 */
void wifi_scanner_update_target_seen(const uint8_t *bssid);

/**
 * @brief Clear all target BSSIDs
 */
void wifi_scanner_clear_targets(void);

/**
 * @brief Clear all network selections
 */
void wifi_scanner_clear_selections(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SCANNER_H

