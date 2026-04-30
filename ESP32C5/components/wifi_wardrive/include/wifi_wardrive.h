#ifndef WIFI_WARDRIVE_H
#define WIFI_WARDRIVE_H

#include "wifi_common.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// GPS FUNCTIONS
// ============================================================================

/**
 * @brief Initialize GPS module
 */
esp_err_t wifi_wardrive_init_gps(void);

/**
 * @brief Get and display GPS fix information
 */
esp_err_t wifi_wardrive_get_gps_fix(void);

/**
 * @brief Check if GPS has valid fix
 */
bool wifi_wardrive_has_gps_fix(void);

/**
 * @brief Get current latitude
 */
float wifi_wardrive_get_latitude(void);

/**
 * @brief Get current longitude
 */
float wifi_wardrive_get_longitude(void);

// ============================================================================
// SD CARD FUNCTIONS
// ============================================================================

/**
 * @brief Initialize SD card (default: 20 MHz, no auto-format)
 */
esp_err_t wifi_wardrive_init_sd(void);

/**
 * @brief Initialize SD card with explicit SPI frequency and format option.
 *        freq_khz: SPI clock (try 20000, then 10000, then 5000 for stubborn cards).
 *        format_if_failed: auto-format as FAT32 if card responds but has no filesystem.
 */
esp_err_t wifi_wardrive_init_sd_ex(uint32_t freq_khz, bool format_if_failed);

/**
 * @brief Check if SD card is mounted
 */
bool wifi_wardrive_is_sd_mounted(void);

/**
 * @brief Format the SD card FAT filesystem (card must be mounted)
 */
esp_err_t wifi_wardrive_format_sd(void);

// ============================================================================
// WARDRIVE FUNCTIONS
// ============================================================================

/**
 * @brief Start wardriving (continuous scan + GPS logging)
 */
esp_err_t wifi_wardrive_start(void);

/**
 * @brief Stop wardriving
 */
esp_err_t wifi_wardrive_stop(void);

/**
 * @brief Check if wardrive is active
 */
bool wifi_wardrive_is_active(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_WARDRIVE_H
