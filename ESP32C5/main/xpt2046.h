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

// Touch is considered active when Z1 raw ADC > this threshold.
// Resting panel contact reads ~0–80; a real touch reads 200–2000+.
// Raise if ghost touches persist; lower if light touches are missed.
#define XPT2046_Z_THRESHOLD  200

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
    // Resting-state dead zone: readings within null_radius of (null_x, null_y) are rejected
    int                 null_x, null_y;
    int                 null_radius;  // 0 = disabled
    // Orientation
    bool                swap_xy;    // swap X and Y axes
    bool                invert_x;   // mirror X axis
    bool                invert_y;   // mirror Y axis
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

/**
 * @brief Read raw (uncalibrated) X/Y ADC values for use during calibration.
 *        Discards the first sample per axis (ADC settling artifact) and
 *        averages 4 subsequent samples.  Does NOT apply calibration mapping,
 *        orientation flags, or null-zone rejection.
 *
 * @param handle   Handle from xpt2046_init()
 * @param raw_x    Output: averaged raw X ADC value (0–4095)
 * @param raw_y    Output: averaged raw Y ADC value (0–4095)
 * @return true if values are in the plausible touch range (100–4000)
 */
bool xpt2046_read_raw_point(xpt2046_handle_t *handle, uint16_t *raw_x, uint16_t *raw_y);

#ifdef __cplusplus
}
#endif

#endif // XPT2046_H
