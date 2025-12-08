#include "lvgl_memory.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "LVGL_MEMORY";
static SemaphoreHandle_t memory_mutex = NULL;

void lvgl_memory_init(void)
{
    memory_mutex = xSemaphoreCreateMutex();
    if (memory_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create memory mutex!");
    }
    ESP_LOGI(TAG, "LVGL custom memory allocator initialized");
}

void lvgl_memory_deinit(void)
{
    if (memory_mutex) {
        vSemaphoreDelete(memory_mutex);
        memory_mutex = NULL;
    }
}

void* lvgl_malloc(size_t size)
{
    if (size == 0) return NULL;
    
    void* ptr = NULL;
    
    // Try PSRAM first, then fallback to internal RAM
    ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr == NULL) {
        ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
    }
    
    if (ptr == NULL) {
        ESP_LOGE(TAG, "Failed to allocate %zu bytes", size);
    } else {
        ESP_LOGI(TAG, "Allocated %zu bytes at %p", size, ptr);
    }
    
    return ptr;
}

void lvgl_free(void* ptr)
{
    if (ptr == NULL) return;
    
    ESP_LOGI(TAG, "Freeing memory at %p", ptr);
    heap_caps_free(ptr);
}

void* lvgl_realloc(void* ptr, size_t new_size)
{
    if (new_size == 0) {
        lvgl_free(ptr);
        return NULL;
    }
    
    if (ptr == NULL) {
        return lvgl_malloc(new_size);
    }
    
    ESP_LOGI(TAG, "Reallocating %p to %zu bytes", ptr, new_size);
    return heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}
