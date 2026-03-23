#include "led_strip.h"

#include <stdlib.h>

typedef struct {
    led_strip_t base;
    uint32_t max_leds;
} compat_led_strip_t;

static compat_led_strip_t *compat_from_handle(led_strip_handle_t strip)
{
    return (compat_led_strip_t *)strip;
}

static esp_err_t compat_set_pixel(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue)
{
    (void)red;
    (void)green;
    (void)blue;

    compat_led_strip_t *compat = compat_from_handle(strip);
    if (compat == NULL || index >= compat->max_leds) {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static esp_err_t compat_set_pixel_rgbw(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue, uint32_t white)
{
    (void)white;
    return compat_set_pixel(strip, index, red, green, blue);
}

static esp_err_t compat_refresh(led_strip_handle_t strip)
{
    return strip ? ESP_OK : ESP_ERR_INVALID_ARG;
}

static esp_err_t compat_clear(led_strip_handle_t strip)
{
    return strip ? ESP_OK : ESP_ERR_INVALID_ARG;
}

static esp_err_t compat_del(led_strip_handle_t strip)
{
    if (strip == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    free(strip);
    return ESP_OK;
}

esp_err_t led_strip_new_rmt_device(const led_strip_config_t *led_config, const led_strip_rmt_config_t *rmt_config, led_strip_handle_t *ret_strip)
{
    (void)rmt_config;

    if (led_config == NULL || ret_strip == NULL || led_config->max_leds == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    compat_led_strip_t *compat = calloc(1, sizeof(*compat));
    if (compat == NULL) {
        return ESP_ERR_NO_MEM;
    }

    compat->base.set_pixel = compat_set_pixel;
    compat->base.set_pixel_rgbw = compat_set_pixel_rgbw;
    compat->base.refresh = compat_refresh;
    compat->base.clear = compat_clear;
    compat->base.del = compat_del;
    compat->max_leds = led_config->max_leds;

    *ret_strip = &compat->base;
    return ESP_OK;
}

esp_err_t led_strip_set_pixel(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue)
{
    if (strip == NULL || strip->set_pixel == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return strip->set_pixel(strip, index, red, green, blue);
}

esp_err_t led_strip_set_pixel_rgbw(led_strip_handle_t strip, uint32_t index, uint32_t red, uint32_t green, uint32_t blue, uint32_t white)
{
    if (strip == NULL || strip->set_pixel_rgbw == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return strip->set_pixel_rgbw(strip, index, red, green, blue, white);
}

esp_err_t led_strip_refresh(led_strip_handle_t strip)
{
    if (strip == NULL || strip->refresh == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return strip->refresh(strip);
}

esp_err_t led_strip_clear(led_strip_handle_t strip)
{
    if (strip == NULL || strip->clear == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return strip->clear(strip);
}

esp_err_t led_strip_del(led_strip_handle_t strip)
{
    if (strip == NULL || strip->del == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return strip->del(strip);
}
