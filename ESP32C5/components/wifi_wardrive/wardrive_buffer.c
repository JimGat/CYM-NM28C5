#include "wardrive_buffer.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "wardrive_buffer";

// Ring buffer state
typedef struct {
    wardrive_detection_t *ring;     // Ring buffer in PSRAM
    volatile uint32_t write_head;   // Next write position
    volatile uint32_t read_head;    // Next read position
    uint32_t capacity;              // Ring capacity
    uint32_t overflow_count;        // Overflow counter
    uint32_t total_added;           // Total detections added
    uint32_t total_flushed;         // Total detections flushed
    SemaphoreHandle_t mutex;        // Protect pointers
} wardrive_buffer_state_t;

static wardrive_buffer_state_t s_buffer = {0};

// Circular index macro
#define RING_NEXT(pos, cap) (((pos) + 1) % (cap))

esp_err_t wardrive_buffer_init(uint32_t capacity) {
    if (s_buffer.ring != NULL) {
        ESP_LOGW(TAG, "Buffer already initialized");
        return ESP_OK;  // Idempotent
    }

    // Allocate ring buffer from PSRAM
    size_t buffer_size = capacity * sizeof(wardrive_detection_t);
    s_buffer.ring = heap_caps_malloc(buffer_size, MALLOC_CAP_SPIRAM);

    if (s_buffer.ring == NULL) {
        ESP_LOGE(TAG, "Failed to allocate %u bytes from PSRAM", (unsigned)buffer_size);
        return ESP_ERR_NO_MEM;
    }

    // Create mutex for pointer synchronization
    s_buffer.mutex = xSemaphoreCreateMutex();
    if (s_buffer.mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        heap_caps_free(s_buffer.ring);
        s_buffer.ring = NULL;
        return ESP_ERR_NO_MEM;
    }

    s_buffer.capacity = capacity;
    s_buffer.write_head = 0;
    s_buffer.read_head = 0;
    s_buffer.overflow_count = 0;
    s_buffer.total_added = 0;
    s_buffer.total_flushed = 0;

    ESP_LOGI(TAG, "Detection buffer initialized: %u slots (~%u KB)",
             capacity, (unsigned)(buffer_size / 1024));

    return ESP_OK;
}

esp_err_t wardrive_buffer_add(const wardrive_detection_t *detection) {
    if (s_buffer.ring == NULL) {
        ESP_LOGE(TAG, "Buffer not initialized");
        return ESP_ERR_INVALID_ARG;
    }

    if (detection == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_buffer.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Timeout taking mutex for add");
        return ESP_ERR_TIMEOUT;
    }

    // Check for collision (write catches read = buffer full)
    uint32_t next_write = RING_NEXT(s_buffer.write_head, s_buffer.capacity);
    if (next_write == s_buffer.read_head) {
        s_buffer.overflow_count++;
        xSemaphoreGive(s_buffer.mutex);
        ESP_LOGW(TAG, "Buffer overflow — detection lost (overflow_count=%u)",
                 s_buffer.overflow_count);
        return ESP_ERR_NO_MEM;  // Buffer full
    }

    // Copy detection into ring
    memcpy(&s_buffer.ring[s_buffer.write_head], detection, sizeof(wardrive_detection_t));
    s_buffer.write_head = next_write;
    s_buffer.total_added++;

    xSemaphoreGive(s_buffer.mutex);

    return ESP_OK;
}

int wardrive_buffer_get_pending(wardrive_detection_t *out, int max_count) {
    if (s_buffer.ring == NULL || out == NULL || max_count <= 0) {
        return 0;
    }

    if (xSemaphoreTake(s_buffer.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Timeout taking mutex for get_pending");
        return 0;
    }

    // Calculate number of readable items
    uint32_t count = 0;
    uint32_t read_pos = s_buffer.read_head;
    uint32_t write_pos = s_buffer.write_head;

    if (read_pos <= write_pos) {
        // Linear range: read_head...write_head
        count = write_pos - read_pos;
    } else {
        // Wrapped range: read_head...end + 0...write_head
        count = (s_buffer.capacity - read_pos) + write_pos;
    }

    // Cap to max_count
    count = (count > (uint32_t)max_count) ? (uint32_t)max_count : count;

    // Copy detections
    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (read_pos + i) % s_buffer.capacity;
        memcpy(&out[i], &s_buffer.ring[idx], sizeof(wardrive_detection_t));
    }

    xSemaphoreGive(s_buffer.mutex);

    return (int)count;
}

void wardrive_buffer_mark_flushed(int count) {
    if (s_buffer.ring == NULL || count <= 0) {
        return;
    }

    if (xSemaphoreTake(s_buffer.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Timeout taking mutex for mark_flushed");
        return;
    }

    s_buffer.read_head = (s_buffer.read_head + count) % s_buffer.capacity;
    s_buffer.total_flushed += count;

    xSemaphoreGive(s_buffer.mutex);
}

int wardrive_buffer_get_fill_percent(void) {
    if (s_buffer.ring == NULL) {
        return 0;
    }

    if (xSemaphoreTake(s_buffer.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return -1;  // Error
    }

    uint32_t count = 0;
    uint32_t read_pos = s_buffer.read_head;
    uint32_t write_pos = s_buffer.write_head;

    if (read_pos <= write_pos) {
        count = write_pos - read_pos;
    } else {
        count = (s_buffer.capacity - read_pos) + write_pos;
    }

    int fill_percent = (count * 100) / s_buffer.capacity;

    xSemaphoreGive(s_buffer.mutex);

    return fill_percent;
}

wardrive_buffer_stats_t wardrive_buffer_get_stats(void) {
    wardrive_buffer_stats_t stats = {0};

    if (s_buffer.ring == NULL) {
        return stats;
    }

    if (xSemaphoreTake(s_buffer.mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        stats.total_added = s_buffer.total_added;
        stats.total_flushed = s_buffer.total_flushed;
        stats.overflow_count = s_buffer.overflow_count;
        stats.current_fill_percent = wardrive_buffer_get_fill_percent();
        xSemaphoreGive(s_buffer.mutex);
    }

    return stats;
}

void wardrive_buffer_free(void) {
    if (s_buffer.ring == NULL) {
        return;
    }

    if (s_buffer.mutex) {
        vSemaphoreDelete(s_buffer.mutex);
        s_buffer.mutex = NULL;
    }

    heap_caps_free(s_buffer.ring);
    s_buffer.ring = NULL;
    s_buffer.write_head = 0;
    s_buffer.read_head = 0;
    s_buffer.capacity = 0;

    ESP_LOGI(TAG, "Detection buffer freed");
}
