#ifndef WIFI_ATTACKS_H
#define WIFI_ATTACKS_H

#include "wifi_common.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// DEAUTH ATTACK
// ============================================================================

/**
 * @brief Start deauth attack on selected targets
 */
esp_err_t wifi_attacks_start_deauth(void);

/**
 * @brief Stop deauth attack
 */
esp_err_t wifi_attacks_stop_deauth(void);

/**
 * @brief Check if deauth attack is active
 */
bool wifi_attacks_is_deauth_active(void);

// ============================================================================
// EVIL TWIN ATTACK
// ============================================================================

/**
 * @brief Evil Twin event types for UI notification
 */
typedef enum {
    EVIL_TWIN_EVENT_DEAUTH_STARTED,
    EVIL_TWIN_EVENT_PORTAL_DEPLOYED,
    EVIL_TWIN_EVENT_CLIENT_CONNECTED,
    EVIL_TWIN_EVENT_CLIENT_DISCONNECTED,
    EVIL_TWIN_EVENT_PASSWORD_PROVIDED,
    EVIL_TWIN_EVENT_PASSWORD_FAILED,
    EVIL_TWIN_EVENT_PASSWORD_VERIFIED,
} evil_twin_event_t;

/**
 * @brief Evil Twin event data structure
 */
typedef struct {
    evil_twin_event_t event;
    char ssid[33];
    char password[64];
} evil_twin_event_data_t;

/**
 * @brief Callback type for Evil Twin events
 */
typedef void (*evil_twin_event_cb_t)(evil_twin_event_data_t *data);

/**
 * @brief Set callback for Evil Twin events
 * @param cb Callback function (NULL to disable)
 */
void wifi_attacks_set_evil_twin_event_cb(evil_twin_event_cb_t cb);

/**
 * @brief Start Evil Twin AP
 * @param ssid SSID to clone
 * @param password Optional password (NULL for open)
 */
esp_err_t wifi_attacks_start_evil_twin(const char *ssid, const char *password);

/**
 * @brief Stop Evil Twin
 */
esp_err_t wifi_attacks_stop_evil_twin(void);

// ============================================================================
// BLACKOUT ATTACK
// ============================================================================

/**
 * @brief Start blackout attack (beacon spam)
 */
esp_err_t wifi_attacks_start_blackout(void);

/**
 * @brief Stop blackout attack
 */
esp_err_t wifi_attacks_stop_blackout(void);

/**
 * @brief Check if blackout attack is active
 */
bool wifi_attacks_is_blackout_active(void);

// ============================================================================
// SAE OVERFLOW ATTACK
// ============================================================================

/**
 * @brief Start SAE overflow attack
 */
esp_err_t wifi_attacks_start_sae_overflow(void);

/**
 * @brief Stop SAE overflow attack
 */
esp_err_t wifi_attacks_stop_sae_overflow(void);

/**
 * @brief Check if SAE overflow attack is active
 */
bool wifi_attacks_is_sae_overflow_active(void);

// ============================================================================
// KARMA ATTACK
// ============================================================================

/**
 * @brief Start Karma attack
 */
esp_err_t wifi_attacks_start_karma(void);

/**
 * @brief Stop Karma attack
 */
esp_err_t wifi_attacks_stop_karma(void);

/**
 * @brief Check if Karma attack is active
 */
bool wifi_attacks_is_karma_active(void);

// ============================================================================
// CAPTIVE PORTAL
// ============================================================================

/**
 * @brief Start captive portal
 * @param ssid SSID for portal AP (optional, NULL for default)
 */
esp_err_t wifi_attacks_start_portal(const char *ssid);

/**
 * @brief Stop captive portal
 */
esp_err_t wifi_attacks_stop_portal(void);

/**
 * @brief Check if portal is active
 */
bool wifi_attacks_is_portal_active(void);

/**
 * @brief Set Karma mode (for internal use - called before starting Evil Twin directly)
 */
void wifi_attacks_set_karma_mode(bool enable);

/**
 * @brief Initialize portal HTML buffer in PSRAM (1MB for large HTML files)
 * @return ESP_OK on success, ESP_ERR_NO_MEM if allocation fails
 */
esp_err_t wifi_attacks_init_portal_html_buffer(void);

/**
 * @brief Free portal HTML buffer
 */
void wifi_attacks_free_portal_html_buffer(void);

// ============================================================================
// COMMON FUNCTIONS
// ============================================================================

/**
 * @brief Stop all active attacks
 */
esp_err_t wifi_attacks_stop_all(void);

/**
 * @brief List HTML files on SD card
 */
void wifi_attacks_list_sd_html(void);
int wifi_attacks_get_sd_html_count(void);
const char *wifi_attacks_get_sd_html_name(int index);
void wifi_attacks_refresh_sd_html_list(void);

/**
 * @brief Select HTML file from SD card for portal
 * @param index Index of HTML file
 */
esp_err_t wifi_attacks_select_sd_html(int index);

/**
 * @brief Get deauth frame count
 */
uint32_t wifi_attacks_get_deauth_count(void);

/**
 * @brief Get beacon frame count
 */
uint32_t wifi_attacks_get_beacon_count(void);

/**
 * @brief Get number of clients connected
 */
uint32_t wifi_attacks_get_clients_connected(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_ATTACKS_H
