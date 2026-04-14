#ifndef XPT2046_H
#define XPT2046_H

#include <stdint.h>
#include <stdbool.h>
#include "driver/spi_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ─── XPT2046 SPI commands ────────────────────────────────────────────────────
// Format: S=1 | A2 A1 A0 (channel) | MODE=0 (12-bit) | SER/DFR=0 (diff) | PD1 PD0=11 (on)
#define XPT2046_CMD_X    0xD3   // Read X position (differential, 12-bit, powered)
#define XPT2046_CMD_Y    0x93   // Read Y position (differential, 12-bit, powered)
#define XPT2046_CMD_Z1   0xB3   // Read Z1 pressure
#define XPT2046_CMD_Z2   0xC3   // Read Z2 pressure

// Touch is considered active when Z1 raw ADC > this threshold
#define XPT2046_Z_THRESHOLD  400

// ─── Calibration defaults for NM-CYD-C5 2.8" 240×320 (portrait) ─────────────
// Adjust these via xpt2046_set_calibration() after running a calibration sketch.
#define XPT2046_X_MIN_DEFAULT   200
#define XPT2046_X_MAX_DEFAULT  3900
#define XPT2046_Y_MIN_DEFAULT   200
#define XPT2046_Y_MAX_DEFAULT  3900

// ─── Types ───────────────────────────────────────────────────────────────────

typedef struct {
    spi_device_handle_t spi;
    int                 cs_gpio;
    uint16_t            screen_w;
    uint16_t            screen_h;
    // Calibration (raw ADC units)
    int                 x_min, x_max;
    int                 y_min, y_max;
} xpt2046_handle_t;

typedef struct {
    uint16_t x;
    uint16_t y;
    bool     touched;
} xpt2046_touch_point_t;

// ─── API ─────────────────────────────────────────────────────────────────────

/**
 * @brief Attach XPT2046 to an already-initialised SPI host.
 *        Must be called AFTER spi_bus_initialize().
 *
 * @param handle     Pointer to caller-allocated handle struct
 * @param host       SPI host (same host as display, e.g. SPI2_HOST)
 * @param cs_gpio    Chip-select GPIO (TOUCH_CS = GPIO 1)
 * @param screen_w   Screen width in pixels  (LCD_H_RES)
 * @param screen_h   Screen height in pixels (LCD_V_RES)
 */
esp_err_t xpt2046_init(xpt2046_handle_t *handle,
                       spi_host_device_t host,
                       int               cs_gpio,
                       uint16_t          screen_w,
                       uint16_t          screen_h);

/**
 * @brief Override the default calibration values.
 *
 * @param handle             Handle from xpt2046_init()
 * @param x_min / x_max      Raw ADC X range (touch left → touch right)
 * @param y_min / y_max      Raw ADC Y range (touch top  → touch bottom)
 */
void xpt2046_set_calibration(xpt2046_handle_t *handle,
                              int x_min, int x_max,
                              int y_min, int y_max);

/**
 * @brief Poll for a touch event (T_IRQ not connected — pure polling).
 *        Safe to call from an LVGL indev read callback.
 *
 * @param handle  Handle from xpt2046_init()
 * @param point   Output: mapped screen coordinates + touched flag
 * @return true if screen is being touched, false otherwise
 */
bool xpt2046_read_touch(xpt2046_handle_t *handle, xpt2046_touch_point_t *point);

#ifdef __cplusplus
}
#endif

#endif // XPT2046_H
