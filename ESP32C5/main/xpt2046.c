#include "xpt2046.h"
#include "freertos/FreeRTOS.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "XPT2046";

// XPT2046 SPI bus speed — must be ≤ 2 MHz (125 kHz internal ADC)
#define XPT2046_SPI_CLK_HZ  (2 * 1000 * 1000)

// Number of averaged samples per axis read (reduces noise)
#define XPT2046_SAMPLES  4

// ─── Internal helpers ────────────────────────────────────────────────────────

/**
 * Send one 8-bit command, receive one 16-bit response.
 * The 12-bit result sits in bits [14:3] of the 16-bit word → shift right 3.
 */
static uint16_t xpt2046_read_raw(xpt2046_handle_t *handle, uint8_t cmd)
{
    uint8_t tx[3] = { cmd, 0x00, 0x00 };
    uint8_t rx[3] = { 0 };

    spi_transaction_t t = {
        .length    = 24,   // 8 cmd + 16 response = 24 clock cycles
        .tx_buffer = tx,
        .rx_buffer = rx,
    };

    spi_device_acquire_bus(handle->spi, portMAX_DELAY);
    spi_device_transmit(handle->spi, &t);
    spi_device_release_bus(handle->spi);

    // Result is in rx[1] (high byte) and rx[2] (low byte), bits [14:3]
    uint16_t raw = ((uint16_t)rx[1] << 8 | rx[2]) >> 3;
    return raw & 0x0FFF;   // 12-bit mask
}

/**
 * Read an axis N times and return the median-filtered average to reduce noise.
 */
static uint16_t xpt2046_read_averaged(xpt2046_handle_t *handle, uint8_t cmd)
{
    uint32_t sum = 0;
    for (int i = 0; i < XPT2046_SAMPLES; i++) {
        sum += xpt2046_read_raw(handle, cmd);
    }
    return (uint16_t)(sum / XPT2046_SAMPLES);
}

/** Clamp and map a raw ADC value to screen pixels. */
static uint16_t xpt2046_map(int raw, int raw_min, int raw_max, int screen_max)
{
    if (raw <= raw_min) return 0;
    if (raw >= raw_max) return (uint16_t)screen_max;
    return (uint16_t)(((long)(raw - raw_min) * screen_max) / (raw_max - raw_min));
}

// ─── Public API ──────────────────────────────────────────────────────────────

esp_err_t xpt2046_init(xpt2046_handle_t *handle,
                       spi_host_device_t host,
                       int               cs_gpio,
                       uint16_t          screen_w,
                       uint16_t          screen_h)
{
    if (!handle) return ESP_ERR_INVALID_ARG;

    memset(handle, 0, sizeof(*handle));
    handle->cs_gpio  = cs_gpio;
    handle->screen_w = screen_w;
    handle->screen_h = screen_h;
    handle->x_min    = XPT2046_X_MIN_DEFAULT;
    handle->x_max    = XPT2046_X_MAX_DEFAULT;
    handle->y_min    = XPT2046_Y_MIN_DEFAULT;
    handle->y_max    = XPT2046_Y_MAX_DEFAULT;

    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = XPT2046_SPI_CLK_HZ,
        .mode           = 0,               // SPI mode 0 (CPOL=0, CPHA=0)
        .spics_io_num   = cs_gpio,
        .queue_size     = 1,
        .pre_cb         = NULL,
        .post_cb        = NULL,
    };

    esp_err_t ret = spi_bus_add_device(host, &devcfg, &handle->spi);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "XPT2046 initialised — CS=GPIO%d, SPI %d Hz, screen %dx%d",
             cs_gpio, XPT2046_SPI_CLK_HZ, screen_w, screen_h);
    ESP_LOGI(TAG, "Calibration: X %d–%d → 0–%d, Y %d–%d → 0–%d",
             handle->x_min, handle->x_max, screen_w - 1,
             handle->y_min, handle->y_max, screen_h - 1);
    return ESP_OK;
}

void xpt2046_set_calibration(xpt2046_handle_t *handle,
                              int x_min, int x_max,
                              int y_min, int y_max)
{
    if (!handle) return;
    handle->x_min = x_min;
    handle->x_max = x_max;
    handle->y_min = y_min;
    handle->y_max = y_max;
    ESP_LOGI(TAG, "Calibration updated: X %d–%d, Y %d–%d", x_min, x_max, y_min, y_max);
}

bool xpt2046_read_touch(xpt2046_handle_t *handle, xpt2046_touch_point_t *point)
{
    if (!handle || !point) return false;

    point->touched = false;

    // Sample Z1 pressure to detect touch (T_IRQ is NC on NM-CYD-C5)
    uint16_t z1 = xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    if (z1 < XPT2046_Z_THRESHOLD) {
        return false;
    }

    // Touch detected — read X and Y (averaged for noise reduction)
    uint16_t raw_x = xpt2046_read_averaged(handle, XPT2046_CMD_X);
    uint16_t raw_y = xpt2046_read_averaged(handle, XPT2046_CMD_Y);

    // Map raw ADC → screen pixels
    point->x       = xpt2046_map(raw_x, handle->x_min, handle->x_max, handle->screen_w  - 1);
    point->y       = xpt2046_map(raw_y, handle->y_min, handle->y_max, handle->screen_h - 1);
    point->touched = true;
    return true;
}
