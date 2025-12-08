#ifndef LVGL_MEMORY_H
#define LVGL_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the custom LVGL memory allocator
 */
void lvgl_memory_init(void);

/**
 * @brief Deinitialize the custom LVGL memory allocator
 */
void lvgl_memory_deinit(void);

/**
 * @brief Custom malloc that prefers PSRAM
 * @param size Size to allocate
 * @return Pointer to allocated memory or NULL on failure
 */
void* lvgl_malloc(size_t size);

/**
 * @brief Custom free function
 * @param ptr Pointer to memory to free
 */
void lvgl_free(void* ptr);

/**
 * @brief Custom realloc function
 * @param ptr Pointer to existing memory
 * @param new_size New size
 * @return Pointer to reallocated memory or NULL on failure
 */
void* lvgl_realloc(void* ptr, size_t new_size);

#ifdef __cplusplus
}
#endif

#endif // LVGL_MEMORY_H
