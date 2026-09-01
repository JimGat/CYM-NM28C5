#include "xpt2046.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_rom_sys.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "XPT2046";

// ─── CYD2USB (two-USB ESP32-2432S028R) touch wiring ─────────────────────────
// The XPT2046 sits on its OWN pins (25/32/39/33/36), separate from the display
// SPI bus. On this board hardware SPI does NOT work for the touch controller
// (returns garbage / 0xFFF) — the witnessmenow ESP-IDF LCD_Touch example bit-
// bangs exactly these pins, and that is what works reliably.
#define XPT2046_GPIO_CLK   25
#define XPT2046_GPIO_MOSI  32
#define XPT2046_GPIO_MISO  39
#define XPT2046_GPIO_IRQ   36   // active low; informational (pressure gate is authoritative)

// Number of raw reads per axis, sorted and averaged with the extremes dropped.
// Bit-banged reads are noisier than hardware SPI, so use the proven 30-sample
// median-style filter from the witnessmenow reference implementation.
#define XPT2046_SAMPLES       30
#define XPT2046_SAMPLES_DROP  1

// ─── GPIO bit-bang helpers (SPI mode 0, MSB first) ───────────────────────────

/** Shift out one 8-bit command byte: set MOSI, then clock low→high. */
static void xpt2046_gpio_write_byte(uint8_t num)
{
    for (int i = 0; i < 8; i++) {
        gpio_set_level(XPT2046_GPIO_MOSI, (num & 0x80) ? 1 : 0);
        num <<= 1;
        gpio_set_level(XPT2046_GPIO_CLK, 0);
        gpio_set_level(XPT2046_GPIO_CLK, 1);
    }
}

/**
 * Send one 8-bit command, clock out the 16-bit response, return the top 12 bits.
 * Timing follows the proven witnessmenow XPT2046 driver: 6 us ADC conversion
 * wait after the command, one extra clock to clear BUSY, then 16 read clocks
 * sampling MISO after the rising edge.
 */
static uint16_t xpt2046_read_raw(xpt2046_handle_t *handle, uint8_t cmd)
{
    uint16_t val = 0;

    gpio_set_level(XPT2046_GPIO_CLK, 0);
    gpio_set_level(XPT2046_GPIO_MOSI, 0);
    gpio_set_level(handle->cs_gpio, 0);        // select touch controller
    xpt2046_gpio_write_byte(cmd);              // 8-bit command, MSB first
    esp_rom_delay_us(6);                       // ADC conversion time (max 6 us)
    gpio_set_level(XPT2046_GPIO_CLK, 0);
    esp_rom_delay_us(1);
    gpio_set_level(XPT2046_GPIO_CLK, 1);       // one clock to clear BUSY
    gpio_set_level(XPT2046_GPIO_CLK, 0);
    for (int i = 0; i < 16; i++) {             // 16 clocks; high 12 bits valid
        val <<= 1;
        gpio_set_level(XPT2046_GPIO_CLK, 0);
        gpio_set_level(XPT2046_GPIO_CLK, 1);
        if (gpio_get_level(XPT2046_GPIO_MISO)) val++;
    }
    val >>= 4;                                 // keep top 12 bits (0–4095)
    gpio_set_level(handle->cs_gpio, 1);        // release chip select

    return val;
}

/**
 * Read an axis N times, sort, drop the extremes and average the rest.
 * Rejects the bit-bang noise spikes the way the reference implementation does.
 */
static uint16_t xpt2046_read_averaged(xpt2046_handle_t *handle, uint8_t cmd)
{
    uint16_t buf[XPT2046_SAMPLES];
    for (int i = 0; i < XPT2046_SAMPLES; i++) {
        buf[i] = xpt2046_read_raw(handle, cmd);
    }
    for (int i = 0; i < XPT2046_SAMPLES - 1; i++) {
        for (int j = i + 1; j < XPT2046_SAMPLES; j++) {
            if (buf[i] > buf[j]) {
                uint16_t t = buf[i]; buf[i] = buf[j]; buf[j] = t;
            }
        }
    }
    uint32_t sum = 0;
    int n = 0;
    for (int i = XPT2046_SAMPLES_DROP; i < XPT2046_SAMPLES - XPT2046_SAMPLES_DROP; i++) {
        sum += buf[i];
        n++;
    }
    return (uint16_t)(sum / n);
}

/**
 * Position-compensated pressure gate (averaged): Z1 + 4095 - Z2.
 * Untouched ≈ 0 (Z1≈0, Z2≈4095); a real touch gives a value well above the
 * threshold anywhere on the panel. Averaging 4 reads suppresses bit-bang noise
 * so spurious Z1 spikes cannot fake a press.
 */
static bool xpt2046_pressure_ok(xpt2046_handle_t *handle)
{
    uint32_t s1 = 0, s2 = 0;
    for (int i = 0; i < 4; i++) s1 += xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    for (int i = 0; i < 4; i++) s2 += xpt2046_read_raw(handle, XPT2046_CMD_Z2);
    int gate = (int)(s1 / 4) + 4095 - (int)(s2 / 4);
    return gate >= XPT2046_Z_THRESHOLD;
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
    (void)host;   // CYD2USB: touch is GPIO bit-banged, not on a hardware SPI bus
    if (!handle) return ESP_ERR_INVALID_ARG;

    memset(handle, 0, sizeof(*handle));
    handle->cs_gpio  = cs_gpio;
    handle->screen_w = screen_w;
    handle->screen_h = screen_h;
    handle->x_min    = XPT2046_X_MIN_DEFAULT;
    handle->x_max    = XPT2046_X_MAX_DEFAULT;
    handle->y_min    = XPT2046_Y_MIN_DEFAULT;
    handle->y_max    = XPT2046_Y_MAX_DEFAULT;

    // Detect whether this CYD2USB actually has a resistive XPT2046 at all.
    // The capacitive variant (CST820) answers on I2C 0x15 with SDA=33/SCL=32,
    // which are the same pads we would bit-bang for the XPT2046 (32=MOSI,
    // 33=CS). If the capacitive IC answers, a resistive chip is NOT present
    // and no amount of GPIO bit-banging will ever produce a touch.
    {
        i2c_master_bus_handle_t cst_bus = NULL;
        i2c_master_bus_config_t bus_cfg = {
            .i2c_port = I2C_NUM_0,
            .sda_io_num = 33,
            .scl_io_num = 32,
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&bus_cfg, &cst_bus) == ESP_OK && cst_bus) {
            esp_err_t probe = i2c_master_probe(cst_bus, 0x15, pdMS_TO_TICKS(50));
            if (probe == ESP_OK) {
                ESP_LOGW(TAG, "CAPACITIVE CST820 PRESENT at I2C 0x15 (SDA=33/SCL=32) — "
                              "this board has NO resistive XPT2046 on 25/32/39/33/36!");
            } else {
                ESP_LOGI(TAG, "I2C probe 0x15: no capacitive IC (rc=%s) — resistive XPT2046 path will be used",
                         esp_err_to_name(probe));
            }
            i2c_del_master_bus(cst_bus);
        }
    }

    // SCLK / MOSI / CS → push-pull outputs
    gpio_config_t out_cfg = {
        .pin_bit_mask = (1ULL << XPT2046_GPIO_CLK) | (1ULL << XPT2046_GPIO_MOSI) | (1ULL << cs_gpio),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&out_cfg);
    // MISO / IRQ → inputs (input-only pads 39/36; no pulls, driven by XPT2046)
    gpio_config_t in_cfg = {
        .pin_bit_mask = (1ULL << XPT2046_GPIO_MISO) | (1ULL << XPT2046_GPIO_IRQ),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&in_cfg);

    gpio_set_level(handle->cs_gpio, 1);   // CS idle high

    ESP_LOGI(TAG, "XPT2046 initialised — CS=GPIO%d, bit-banged SPI (CLK=%d MOSI=%d MISO=%d), screen %dx%d",
             cs_gpio, XPT2046_GPIO_CLK, XPT2046_GPIO_MOSI, XPT2046_GPIO_MISO, screen_w, screen_h);
    ESP_LOGI(TAG, "Calibration: X %d–%d → 0–%d, Y %d–%d → 0–%d",
             handle->x_min, handle->x_max, screen_w - 1,
             handle->y_min, handle->y_max, screen_h - 1);

    // Send a dummy Z1 read to wake the XPT2046 from power-down mode.
    // The chip starts powered-down; the first SPI command brings it up.
    uint16_t wakeup = xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    ESP_LOGI(TAG, "XPT2046 wakeup read: z1_raw=%u (expect < 100 if untouched)", wakeup);

    // Diagnostic probe: read all axes untouched so the boot log shows whether
    // the chip answers at all. If every value is 0 or 4095, the touch IC on
    // this CYD2USB is NOT an XPT2046 on these pins (it may be a capacitive
    // CST820 on I2C instead) and the UI will never see presses.
    uint16_t p_x  = xpt2046_read_averaged(handle, XPT2046_CMD_X);
    uint16_t p_y  = xpt2046_read_averaged(handle, XPT2046_CMD_Y);
    uint16_t p_z1 = xpt2046_read_raw(handle, XPT2046_CMD_Z1);
    uint16_t p_z2 = xpt2046_read_raw(handle, XPT2046_CMD_Z2);
    ESP_LOGI(TAG, "XPT2046 probe (untouched): X=%u Y=%u Z1=%u Z2=%u | gate=%d (thr=%d)\n"
                  "  - values in 0..4095 with Z1<Z2 and a gate > %d mean the resistive chip is alive\n"
                  "  - all zeros or all 4095 mean NO XPT2046 on these pins (likely capacitive CST820)",
             p_x, p_y, p_z1, p_z2,
             (int)p_z1 + 4095 - (int)p_z2, XPT2046_Z_THRESHOLD, XPT2046_Z_THRESHOLD);

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

    // Position-compensated pressure gate (see xpt2046_pressure_ok).
    if (!xpt2046_pressure_ok(handle)) {
        return false;
    }

    uint16_t raw_x = xpt2046_read_averaged(handle, XPT2046_CMD_X);
    uint16_t raw_y = xpt2046_read_averaged(handle, XPT2046_CMD_Y);

    // Z is the sole touched/not-touched gate — do not range-check raw_x/raw_y here.
    // Near the physical screen edges the ADC legitimately reads above 4000 or below 100;
    // a range check silently drops those touches and creates dead zones at the edges.

    // Reject readings within the null zone (ghost touches at the panel resting position).
    if (handle->null_radius > 0) {
        int dx = (int)raw_x - handle->null_x;
        int dy = (int)raw_y - handle->null_y;
        if ((dx * dx + dy * dy) < (handle->null_radius * handle->null_radius)) {
            return false;
        }
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

    ESP_LOGD(TAG, "TOUCH raw_x=%u raw_y=%u → screen(%u,%u)", raw_x, raw_y, px, py);
    return true;
}

bool xpt2046_read_raw_point(xpt2046_handle_t *handle, uint16_t *out_x, uint16_t *out_y)
{
    if (!handle || !out_x || !out_y) return false;

    // Same pressure gate as xpt2046_read_touch.
    if (!xpt2046_pressure_ok(handle)) return false;

    *out_x = xpt2046_read_averaged(handle, XPT2046_CMD_X);
    *out_y = xpt2046_read_averaged(handle, XPT2046_CMD_Y);
    return true;  // Z already confirmed touch; don't range-filter raw values
}
