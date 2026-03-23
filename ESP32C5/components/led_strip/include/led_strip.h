#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LED_STRIP_RMT_CLK_SRC_DEFAULT 0

typedef union {
    struct {
        uint32_t r_pos : 3;
        uint32_t g_pos : 3;
        uint32_t b_pos : 3;
        uint32_t w_pos : 3;
        uint32_t reserved : 16;
        uint32_t num_components : 4;
    } format;
    uint32_t format_id;
} led_color_component_format_t;

#define LED_STRIP_COLOR_COMPONENT_FMT_GRB ((led_color_component_format_t){ \
    .format = { \
        .r_pos = 1, \
        .g_pos = 0, \
        .b_pos = 2, \
        .w_pos = 3, \
        .reserved = 0, \
        .num_components = 3, \
    }, \
})

#define LED_STRIP_COLOR_COMPONENT_FMT_GRBW ((led_color_component_format_t){ \
    .format = { \
        .r_pos = 1, \
        .g_pos = 0, \
        .b_pos = 2, \
        .w_pos = 3, \
        .reserved = 0, \
        .num_components = 4, \
    }, \
})

#define LED_STRIP_COLOR_COMPONENT_FMT_RGB ((led_color_component_format_t){ \
    .format = { \
        .r_pos = 0, \
        .g_pos = 1, \
        .b_pos = 2, \
        .w_pos = 3, \
        .reserved = 0, \
        .num_components = 3, \
    }, \
})

#define LED_STRIP_COLOR_COMPONENT_FMT_RGBW ((led_color_component_format_t){ \
    .format = { \
        .r_pos = 0, \
        .g_pos = 1, \
        .b_pos = 2, \
        .w_pos = 3, \
        .reserved = 0, \
        .num_components = 4, \
    }, \
})

typedef enum {
    LED_MODEL_WS2812 = 0,
    LED_MODEL_SK6812,
    LED_MODEL_WS2811,
    LED_MODEL_INVALID,
} led_model_t;

typedef struct {
    uint32_t invert_out : 1;
} led_strip_extra_flags_t;

typedef struct {
    int strip_gpio_num;
    uint32_t max_leds;
    led_model_t led_model;
    led_color_component_format_t color_component_format;
    led_strip_extra_flags_t flags;
} led_strip_config_t;

typedef struct {
    uint32_t with_dma : 1;
} led_strip_rmt_extra_flags_t;

typedef struct {
    int clk_src;
    uint32_t resolution_hz;
    size_t mem_block_symbols;
    led_strip_rmt_extra_flags_t flags;
} led_strip_rmt_config_t;

typedef struct led_strip_t led_strip_t;
typedef led_strip_t *led_strip_handle_t;

struct led_strip_t {
    esp_err_t (*set_pixel)(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue);
    esp_err_t (*set_pixel_rgbw)(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue, uint32_t white);
    esp_err_t (*refresh)(led_strip_handle_t strip);
    esp_err_t (*clear)(led_strip_handle_t strip);
    esp_err_t (*del)(led_strip_handle_t strip);
};

esp_err_t led_strip_new_rmt_device(const led_strip_config_t *led_config, const led_strip_rmt_config_t *rmt_config, led_strip_handle_t *ret_strip);
esp_err_t led_strip_set_pixel(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue);
esp_err_t led_strip_set_pixel_rgbw(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue, uint32_t white);
esp_err_t led_strip_refresh(led_strip_handle_t strip);
esp_err_t led_strip_clear(led_strip_handle_t strip);
esp_err_t led_strip_del(led_strip_handle_t strip);

#ifdef __cplusplus
}
#endif
