// Real WS2812 driver via ESP-IDF 6.x RMT TX peripheral.
// Replaces the earlier no-op stub.

#include "led_strip.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_encoder.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "led_strip_rmt";

#define RMT_RESOLUTION_HZ  10000000u   // 10 MHz → 100 ns per tick

// ── WS2812 encoder ──────────────────────────────────────────────────────────

typedef struct {
    rmt_encoder_t base;
    rmt_encoder_t *bytes_encoder;
    rmt_encoder_t *copy_encoder;
    int state;
    rmt_symbol_word_t reset_code;
} ws2812_encoder_t;

RMT_ENCODER_FUNC_ATTR
static size_t ws2812_encode(rmt_encoder_t *encoder, rmt_channel_handle_t channel,
                            const void *data, size_t size, rmt_encode_state_t *ret_state)
{
    ws2812_encoder_t *enc = __containerof(encoder, ws2812_encoder_t, base);
    rmt_encode_state_t session = RMT_ENCODING_RESET, state = RMT_ENCODING_RESET;
    size_t n = 0;
    switch (enc->state) {
    case 0:
        n += enc->bytes_encoder->encode(enc->bytes_encoder, channel, data, size, &session);
        if (session & RMT_ENCODING_COMPLETE) enc->state = 1;
        if (session & RMT_ENCODING_MEM_FULL) { state |= RMT_ENCODING_MEM_FULL; goto out; }
        // fall-through
    case 1:
        n += enc->copy_encoder->encode(enc->copy_encoder, channel,
                                       &enc->reset_code, sizeof(enc->reset_code), &session);
        if (session & RMT_ENCODING_COMPLETE) {
            enc->state = RMT_ENCODING_RESET;
            state |= RMT_ENCODING_COMPLETE;
        }
        if (session & RMT_ENCODING_MEM_FULL) { state |= RMT_ENCODING_MEM_FULL; goto out; }
    }
out:
    *ret_state = state;
    return n;
}

static esp_err_t ws2812_encode_del(rmt_encoder_t *encoder)
{
    ws2812_encoder_t *enc = __containerof(encoder, ws2812_encoder_t, base);
    rmt_del_encoder(enc->bytes_encoder);
    rmt_del_encoder(enc->copy_encoder);
    free(enc);
    return ESP_OK;
}

RMT_ENCODER_FUNC_ATTR
static esp_err_t ws2812_encode_reset(rmt_encoder_t *encoder)
{
    ws2812_encoder_t *enc = __containerof(encoder, ws2812_encoder_t, base);
    rmt_encoder_reset(enc->bytes_encoder);
    rmt_encoder_reset(enc->copy_encoder);
    enc->state = RMT_ENCODING_RESET;
    return ESP_OK;
}

static esp_err_t ws2812_encoder_new(uint32_t resolution, rmt_encoder_handle_t *out)
{
    esp_err_t ret = ESP_OK;
    ws2812_encoder_t *enc = rmt_alloc_encoder_mem(sizeof(*enc));
    ESP_RETURN_ON_FALSE(enc, ESP_ERR_NO_MEM, TAG, "no mem for WS2812 encoder");
    enc->base.encode = ws2812_encode;
    enc->base.del    = ws2812_encode_del;
    enc->base.reset  = ws2812_encode_reset;

    // WS2812 timing at 10 MHz resolution (100 ns/tick):
    // T0H=3 ticks(300ns), T0L=9 ticks(900ns)
    // T1H=9 ticks(900ns), T1L=3 ticks(300ns)
    rmt_bytes_encoder_config_t bytes_cfg = {
        .bit0 = {
            .level0 = 1, .duration0 = (uint16_t)(0.3 * resolution / 1000000),
            .level1 = 0, .duration1 = (uint16_t)(0.9 * resolution / 1000000),
        },
        .bit1 = {
            .level0 = 1, .duration0 = (uint16_t)(0.9 * resolution / 1000000),
            .level1 = 0, .duration1 = (uint16_t)(0.3 * resolution / 1000000),
        },
        .flags.msb_first = 1,
    };
    ESP_GOTO_ON_ERROR(rmt_new_bytes_encoder(&bytes_cfg, &enc->bytes_encoder),
                      err, TAG, "bytes encoder failed");
    rmt_copy_encoder_config_t copy_cfg = {};
    ESP_GOTO_ON_ERROR(rmt_new_copy_encoder(&copy_cfg, &enc->copy_encoder),
                      err, TAG, "copy encoder failed");

    uint32_t reset_ticks = resolution / 1000000 * 50 / 2;  // 50 µs reset
    enc->reset_code = (rmt_symbol_word_t){
        .level0 = 0, .duration0 = reset_ticks,
        .level1 = 0, .duration1 = reset_ticks,
    };
    *out = &enc->base;
    return ESP_OK;
err:
    if (enc->bytes_encoder) rmt_del_encoder(enc->bytes_encoder);
    if (enc->copy_encoder)  rmt_del_encoder(enc->copy_encoder);
    free(enc);
    return ret;
}

// ── Strip instance ───────────────────────────────────────────────────────────

typedef struct {
    led_strip_t base;
    rmt_channel_handle_t chan;
    rmt_encoder_handle_t encoder;
    uint32_t max_leds;
    uint8_t *buf;   // 3 bytes per LED, wire order G-R-B
} rmt_led_strip_t;

static esp_err_t rmt_strip_set_pixel(led_strip_handle_t strip, uint32_t idx,
                                     uint32_t r, uint32_t g, uint32_t b)
{
    rmt_led_strip_t *s = __containerof(strip, rmt_led_strip_t, base);
    if (idx >= s->max_leds) return ESP_ERR_INVALID_ARG;
    s->buf[idx * 3 + 0] = (uint8_t)g;
    s->buf[idx * 3 + 1] = (uint8_t)r;
    s->buf[idx * 3 + 2] = (uint8_t)b;
    return ESP_OK;
}

static esp_err_t rmt_strip_set_pixel_rgbw(led_strip_handle_t strip, uint32_t idx,
                                           uint32_t r, uint32_t g, uint32_t b, uint32_t w)
{
    (void)w;
    return rmt_strip_set_pixel(strip, idx, r, g, b);
}

static esp_err_t rmt_strip_refresh(led_strip_handle_t strip)
{
    rmt_led_strip_t *s = __containerof(strip, rmt_led_strip_t, base);
    rmt_transmit_config_t tx_cfg = { .loop_count = 0 };
    esp_err_t ret = rmt_transmit(s->chan, s->encoder, s->buf, s->max_leds * 3, &tx_cfg);
    if (ret == ESP_OK) rmt_tx_wait_all_done(s->chan, pdMS_TO_TICKS(100));
    return ret;
}

static esp_err_t rmt_strip_clear(led_strip_handle_t strip)
{
    rmt_led_strip_t *s = __containerof(strip, rmt_led_strip_t, base);
    memset(s->buf, 0, s->max_leds * 3);
    return rmt_strip_refresh(strip);
}

static esp_err_t rmt_strip_del(led_strip_handle_t strip)
{
    rmt_led_strip_t *s = __containerof(strip, rmt_led_strip_t, base);
    rmt_disable(s->chan);
    rmt_del_channel(s->chan);
    rmt_del_encoder(s->encoder);
    free(s->buf);
    free(s);
    return ESP_OK;
}

// ── Public API ───────────────────────────────────────────────────────────────

esp_err_t led_strip_new_rmt_device(const led_strip_config_t *led_cfg,
                                    const led_strip_rmt_config_t *rmt_cfg,
                                    led_strip_handle_t *ret_strip)
{
    if (!led_cfg || !ret_strip || led_cfg->max_leds == 0) return ESP_ERR_INVALID_ARG;

    esp_err_t ret = ESP_OK;
    rmt_led_strip_t *s = calloc(1, sizeof(*s));
    ESP_RETURN_ON_FALSE(s, ESP_ERR_NO_MEM, TAG, "no mem for strip");

    s->buf = calloc(led_cfg->max_leds, 3);
    ESP_GOTO_ON_FALSE(s->buf, ESP_ERR_NO_MEM, err, TAG, "no mem for pixel buffer");
    s->max_leds = led_cfg->max_leds;

    uint32_t res = (rmt_cfg && rmt_cfg->resolution_hz) ? rmt_cfg->resolution_hz : RMT_RESOLUTION_HZ;

    rmt_tx_channel_config_t tx_cfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .gpio_num          = led_cfg->strip_gpio_num,
        .mem_block_symbols = 64,
        .resolution_hz     = res,
        .trans_queue_depth = 4,
        .flags.invert_out  = led_cfg->flags.invert_out,
        .flags.with_dma    = rmt_cfg ? rmt_cfg->flags.with_dma : 0,
    };
    ESP_GOTO_ON_ERROR(rmt_new_tx_channel(&tx_cfg, &s->chan),    err, TAG, "rmt_new_tx_channel");
    ESP_GOTO_ON_ERROR(ws2812_encoder_new(res, &s->encoder),     err, TAG, "ws2812_encoder_new");
    ESP_GOTO_ON_ERROR(rmt_enable(s->chan),                      err, TAG, "rmt_enable");

    s->base.set_pixel      = rmt_strip_set_pixel;
    s->base.set_pixel_rgbw = rmt_strip_set_pixel_rgbw;
    s->base.refresh        = rmt_strip_refresh;
    s->base.clear          = rmt_strip_clear;
    s->base.del            = rmt_strip_del;

    ESP_LOGI(TAG, "WS2812 on GPIO%d, res=%"PRIu32" Hz, %"PRIu32" LED(s)",
             led_cfg->strip_gpio_num, res, led_cfg->max_leds);
    *ret_strip = &s->base;
    return ESP_OK;

err:
    if (s->chan)    { rmt_disable(s->chan); rmt_del_channel(s->chan); }
    if (s->encoder) rmt_del_encoder(s->encoder);
    free(s->buf);
    free(s);
    return ret;
}

esp_err_t led_strip_set_pixel(led_strip_handle_t strip, uint32_t idx,
                               uint32_t r, uint32_t g, uint32_t b)
{
    if (!strip || !strip->set_pixel) return ESP_ERR_INVALID_ARG;
    return strip->set_pixel(strip, idx, r, g, b);
}

esp_err_t led_strip_set_pixel_rgbw(led_strip_handle_t strip, uint32_t idx,
                                    uint32_t r, uint32_t g, uint32_t b, uint32_t w)
{
    if (!strip || !strip->set_pixel_rgbw) return ESP_ERR_INVALID_ARG;
    return strip->set_pixel_rgbw(strip, idx, r, g, b, w);
}

esp_err_t led_strip_refresh(led_strip_handle_t strip)
{
    if (!strip || !strip->refresh) return ESP_ERR_INVALID_ARG;
    return strip->refresh(strip);
}

esp_err_t led_strip_clear(led_strip_handle_t strip)
{
    if (!strip || !strip->clear) return ESP_ERR_INVALID_ARG;
    return strip->clear(strip);
}

esp_err_t led_strip_del(led_strip_handle_t strip)
{
    if (!strip || !strip->del) return ESP_ERR_INVALID_ARG;
    return strip->del(strip);
}
