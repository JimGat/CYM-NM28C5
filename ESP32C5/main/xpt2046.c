#include "xpt2046.h"
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
    // Use static buffers — spi_device_transmit requires DMA-accessible memory;
    // stack allocations are unreliable on shared-DMA buses.
    static uint8_t tx[3];
    static uint8_t rx[3];
    tx[0] = cmd; tx[1] = 0x00; tx[2] = 0x00;
    rx[0] = 0;   rx[1] = 0;    rx[2] = 0;

    spi_transaction_t t = {
        .length    = 24,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };

    // spi_device_transmit (ISR-based queue, not polling) — avoids polling_mutex
    // which the SD SPI driver holds via spi_device_acquire_bus during file I/O.
    esp_err_t ret = spi_device_transmit(handle->spi, &t);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPI tx failed (cmd=0x%02x): %s", cmd, esp_err_to_name(ret));
        return 0;
    }

    // Result is in rx[1] (high byte) and rx[2] (low byte), bits [14:3]
    uint16_t raw = ((uint16_t)rx[1] << 8 | rx[2]) >> 3;
    return raw & 0x0FFF;
}

/**
 * Read an axis N times and return the average.
 * The first sample is discarded — the XPT2046 ADC capacitor always needs one
 * settling cycle when switching channels, producing a spurious high reading.
 */
static uint16_t xpt2046_read_averaged(xpt2046_handle_t *handle, uint8_t cmd)
{
    xpt2046_read_raw(handle, cmd);  // discard: ADC capacitor settling artifact
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

    // Send a dummy Z1 read to wake the XPT2046 from power-down mode.
    // The chip starts powered-down; first SPI command with PD=11 brings it up.
    uint16_t wakeup = xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    ESP_LOGI(TAG, "XPT2046 wakeup read: z1_raw=%u (expect < 100 if untouched)", wakeup);

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

    // Z1 pressure gate — primary touch/no-touch discriminator.
    // T_IRQ is NC on NM-CYD-C5 so we poll. XPT2046 Z1 reads near 0 when the
    // panel is floating and climbs to hundreds/thousands under real finger pressure.
    uint16_t z1 = xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    if (z1 < XPT2046_Z_THRESHOLD) {
        return false;
    }

    uint16_t raw_x = xpt2046_read_averaged(handle, XPT2046_CMD_X);
    uint16_t raw_y = xpt2046_read_averaged(handle, XPT2046_CMD_Y);

    // Values at or near 0 or 4095 mean the panel is floating (not touched).
    bool valid_x = (raw_x > 100 && raw_x < 4000);
    bool valid_y = (raw_y > 100 && raw_y < 4000);

    // Reject readings within the null zone (resting-state ghost touch at rest position).
    if (valid_x && valid_y && handle->null_radius > 0) {
        int dx = (int)raw_x - handle->null_x;
        int dy = (int)raw_y - handle->null_y;
        if ((dx * dx + dy * dy) < (handle->null_radius * handle->null_radius)) {
            valid_x = false;
        }
    }

    if (!valid_x || !valid_y) {
        return false;
    }

    // Apply axis swap / invert before mapping
    uint16_t map_x = handle->swap_xy ? raw_y : raw_x;
    uint16_t map_y = handle->swap_xy ? raw_x : raw_y;

    int x_min = handle->swap_xy ? handle->y_min : handle->x_min;
    int x_max = handle->swap_xy ? handle->y_max : handle->x_max;
    int y_min = handle->swap_xy ? handle->x_min : handle->y_min;
    int y_max = handle->swap_xy ? handle->x_max : handle->y_max;

    uint16_t px = xpt2046_map(map_x, x_min, x_max, handle->screen_w - 1);
    uint16_t py = xpt2046_map(map_y, y_min, y_max, handle->screen_h - 1);

    if (handle->invert_x) px = (handle->screen_w - 1) - px;
    if (handle->invert_y) py = (handle->screen_h - 1) - py;

    point->x       = px;
    point->y       = py;
    point->touched = true;

    ESP_LOGD(TAG, "TOUCH z1=%u raw_x=%u raw_y=%u → screen(%u,%u)", z1, raw_x, raw_y, px, py);
    return true;
}

bool xpt2046_read_raw_point(xpt2046_handle_t *handle, uint16_t *out_x, uint16_t *out_y)
{
    if (!handle || !out_x || !out_y) return false;

    // Discard first sample per axis (ADC settling), then average 4 samples
    xpt2046_read_raw(handle, XPT2046_CMD_X);
    uint32_t sx = 0;
    for (int i = 0; i < 4; i++) sx += xpt2046_read_raw(handle, XPT2046_CMD_X);

    xpt2046_read_raw(handle, XPT2046_CMD_Y);
    uint32_t sy = 0;
    for (int i = 0; i < 4; i++) sy += xpt2046_read_raw(handle, XPT2046_CMD_Y);

    uint16_t x = (uint16_t)(sx / 4);
    uint16_t y = (uint16_t)(sy / 4);
    *out_x = x;
    *out_y = y;
    return (x > 100 && x < 4000 && y > 100 && y < 4000);
}
