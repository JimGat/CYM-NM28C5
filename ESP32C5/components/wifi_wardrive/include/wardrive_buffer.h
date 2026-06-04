#ifndef WARDRIVE_BUFFER_H
#define WARDRIVE_BUFFER_H

#include "esp_wifi.h"
#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Detection record structure (stored in PSRAM ring buffer)
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    float latitude;
    float longitude;
    float altitude;
    int satellites;
} wardrive_detection_t;

// Statistics for monitoring
typedef struct {
    uint32_t total_added;
    uint32_t total_flushed;
    uint32_t overflow_count;
    int current_fill_percent;
} wardrive_buffer_stats_t;

/**
 * Initialize detection buffer (ring buffer in PSRAM)
 * @param capacity Maximum number of detections to buffer
 * @return ESP_OK on success, ESP_ERR_NO_MEM if PSRAM allocation fails
 */
esp_err_t wardrive_buffer_init(uint32_t capacity);

/**
 * Add a detection to the buffer (non-blocking, O(1))
 * @param detection Pointer to detection record
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if buffer not initialized
 */
esp_err_t wardrive_buffer_add(const wardrive_detection_t *detection);

/**
 * Get pending detections for flushing
 * Does NOT advance read pointer; caller must call wardrive_buffer_mark_flushed()
 * @param out Output array for detections
 * @param max_count Maximum detections to read
 * @return Number of detections read (0 if buffer empty)
 */
int wardrive_buffer_get_pending(wardrive_detection_t *out, int max_count);

/**
 * Mark detections as flushed (advances read pointer)
 * @param count Number of detections that were successfully flushed
 */
void wardrive_buffer_mark_flushed(int count);

/**
 * Get current buffer fill percentage
 * @return Fill percentage (0-100)
 */
int wardrive_buffer_get_fill_percent(void);

/**
 * Get buffer statistics
 * @return Statistics structure
 */
wardrive_buffer_stats_t wardrive_buffer_get_stats(void);

/**
 * Clean up and free buffer
 */
void wardrive_buffer_free(void);

#ifdef __cplusplus
}
#endif

#endif // WARDRIVE_BUFFER_H
