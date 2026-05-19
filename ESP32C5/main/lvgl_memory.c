#include "lvgl_memory.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "LVGL_MEMORY";

void lvgl_memory_init(void)
{
    ESP_LOGI(TAG, "LVGL custom memory allocator initialized (PSRAM)");
}

void lvgl_memory_deinit(void) {}

void* lvgl_malloc(size_t size)
{
    if (size == 0) return NULL;
    void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr == NULL) {
        ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
        if (ptr == NULL)
            ESP_LOGE(TAG, "OOM: failed to allocate %zu bytes", size);
    }
    return ptr;
}

void lvgl_free(void* ptr)
{
    if (ptr == NULL) return;
    heap_caps_free(ptr);
}

void* lvgl_realloc(void* ptr, size_t new_size)
{
    if (new_size == 0) { lvgl_free(ptr); return NULL; }
    if (ptr == NULL) return lvgl_malloc(new_size);
    void *np = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (np == NULL) np = heap_caps_realloc(ptr, new_size, MALLOC_CAP_8BIT);
    return np;
}
