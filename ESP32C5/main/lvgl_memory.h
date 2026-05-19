#ifndef LVGL_MEMORY_H
#define LVGL_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void lvgl_memory_init(void);
void lvgl_memory_deinit(void);
void* lvgl_malloc(size_t size);
void lvgl_free(void* ptr);
void* lvgl_realloc(void* ptr, size_t new_size);

#ifdef __cplusplus
}
#endif

// When included by lv_mem.c, LV_MEM_CUSTOM_ALLOC is already defined as malloc
// by lv_conf_internal.h. Override it here so LVGL uses PSRAM instead of internal RAM.
#ifdef LV_MEM_CUSTOM_ALLOC
#undef LV_MEM_CUSTOM_ALLOC
#define LV_MEM_CUSTOM_ALLOC   lvgl_malloc
#undef LV_MEM_CUSTOM_FREE
#define LV_MEM_CUSTOM_FREE    lvgl_free
#undef LV_MEM_CUSTOM_REALLOC
#define LV_MEM_CUSTOM_REALLOC lvgl_realloc
#endif

#endif // LVGL_MEMORY_H
