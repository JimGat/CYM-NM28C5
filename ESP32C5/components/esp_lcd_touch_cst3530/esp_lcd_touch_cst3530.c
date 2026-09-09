/*
 * SPDX-FileCopyrightText: 2015-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_check.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_touch.h"
#include "esp_lcd_touch_cst3530.h"

static const char *TAG = "CST3530";

/* CST3530 commands (32-bit, sent MSB-first over I2C) */
#define ESP_LCD_TOUCH_CST3530_READ_COMMAND      (0xD0070000)
#define ESP_LCD_TOUCH_CST3530_INFO_COMMAND      (0xD0030000)
#define ESP_LCD_TOUCH_CST3530_SLEEP_COMMAND     (0xD00022AB)
#define ESP_LCD_TOUCH_CST3530_CLEAR_COMMAND     (0xD00002AB)
#define ESP_LCD_TOUCH_CST3530_MAX_FINGER_NUM    (5)
#define ESP_LCD_TOUCH_CST3530_MAX_READ_BYTES    (32)
#define ESP_CST3530_TOUCH_MAX_BUTTONS           (4)

/* Per-point byte offset from base to the last byte we read (event/id byte) */
#define CST3530_POINT_OFFSET_MAX                (8)

/*
 * Private I2C context: holds the device handle used for direct I2C
 * communication.  The I2C master bus handle is passed via driver_data.
 *
 * NOTE: We bypass esp_lcd_panel_io_* because those functions treat
 * negative command values (MSB set, e.g. 0xD0070000 cast to int) as
 * "no command" and skip sending them.  The CST3530 requires the full
 * 32-bit command word.
 */
typedef struct {
    i2c_master_dev_handle_t dev_handle;
} cst3530_i2c_ctx_t;

/*******************************************************************************
* Function declarations
*******************************************************************************/
static esp_err_t esp_lcd_touch_cst3530_read_data(esp_lcd_touch_handle_t tp);
static bool esp_lcd_touch_cst3530_get_xy(esp_lcd_touch_handle_t tp, uint16_t *x, uint16_t *y, uint16_t *strength,
                                       uint8_t *point_num, uint8_t max_point_num);
/* get_track_id not used — removed for esp_lcd_touch v1.1.2 compat */
static esp_err_t esp_lcd_touch_cst3530_exit_sleep(esp_lcd_touch_handle_t tp);
static esp_err_t esp_lcd_touch_cst3530_enter_sleep(esp_lcd_touch_handle_t tp);
#if (CONFIG_ESP_LCD_TOUCH_MAX_BUTTONS > 0)
static esp_err_t esp_lcd_touch_cst3530_get_button_state(esp_lcd_touch_handle_t tp, uint8_t n, uint8_t *state);
#endif
static esp_err_t esp_lcd_touch_cst3530_del(esp_lcd_touch_handle_t tp);

/* Direct I2C read/write */
static esp_err_t touch_cst3530_i2c_read(esp_lcd_touch_handle_t tp, uint32_t cmd, uint8_t *data, uint8_t len);
static esp_err_t touch_cst3530_i2c_write_cmd(esp_lcd_touch_handle_t tp, uint32_t cmd);

/* Helpers */
static esp_err_t touch_cst3530_reset(esp_lcd_touch_handle_t tp);
static esp_err_t touch_cst3530_read_cfg(esp_lcd_touch_handle_t tp);
static uint16_t touch_cst3530_checksum(uint16_t init_val, const uint8_t *buf, uint16_t len);

/* Pack a 32-bit command word MSB-first into a 4-byte buffer */
static inline void pack_cmd(uint32_t cmd, uint8_t buf[4])
{
    buf[0] = (uint8_t)(cmd >> 24);
    buf[1] = (uint8_t)(cmd >> 16);
    buf[2] = (uint8_t)(cmd >> 8);
    buf[3] = (uint8_t)(cmd);
}

/* Write 0xD0000400, wait, write 0xD0000400 again (shared by sleep/wake) */
static esp_err_t touch_cst3530_pre_sleep(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_ERROR(touch_cst3530_i2c_write_cmd(tp, 0xD0000400), TAG, "pre-sleep cmd 1 failed");
    vTaskDelay(pdMS_TO_TICKS(2));
    ESP_RETURN_ON_ERROR(touch_cst3530_i2c_write_cmd(tp, 0xD0000400), TAG, "pre-sleep cmd 2 failed");
    return ESP_OK;
}

/*******************************************************************************
* Public API
*******************************************************************************/

esp_err_t esp_lcd_touch_new_i2c_cst3530(const esp_lcd_panel_io_handle_t io, const esp_lcd_touch_config_t *config,
                                      esp_lcd_touch_handle_t *out_touch)
{
    esp_err_t ret = ESP_OK;

    ESP_RETURN_ON_FALSE(io != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid io");
    ESP_RETURN_ON_FALSE(config != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid config");
    ESP_RETURN_ON_FALSE(out_touch != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid out_touch");

    esp_lcd_touch_handle_t tp = heap_caps_calloc(1, sizeof(esp_lcd_touch_t), MALLOC_CAP_DEFAULT);
    ESP_GOTO_ON_FALSE(tp, ESP_ERR_NO_MEM, err, TAG, "no mem");

    tp->io = io;
    tp->read_data = esp_lcd_touch_cst3530_read_data;
    tp->get_xy = esp_lcd_touch_cst3530_get_xy;
    /* tp->get_track_id not available in esp_lcd_touch v1.1.2 — omitted */
#if (CONFIG_ESP_LCD_TOUCH_MAX_BUTTONS > 0)
    tp->get_button_state = esp_lcd_touch_cst3530_get_button_state;
#endif
    tp->del = esp_lcd_touch_cst3530_del;
    tp->enter_sleep = esp_lcd_touch_cst3530_enter_sleep;
    tp->exit_sleep = esp_lcd_touch_cst3530_exit_sleep;
    tp->data.lock.owner = portMUX_FREE_VAL;

    memcpy(&tp->config, config, sizeof(esp_lcd_touch_config_t));

    /* ---- Setup direct I2C (bypass panel IO) ---- */
    i2c_master_bus_handle_t bus = (i2c_master_bus_handle_t)tp->config.driver_data;

    if (bus != NULL) {
        cst3530_i2c_ctx_t *ctx = (cst3530_i2c_ctx_t *)heap_caps_calloc(1, sizeof(cst3530_i2c_ctx_t), MALLOC_CAP_DEFAULT);
        ESP_GOTO_ON_FALSE(ctx, ESP_ERR_NO_MEM, err, TAG, "no mem for I2C ctx");

        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address = ESP_LCD_TOUCH_IO_I2C_CST3530_ADDRESS,
            .scl_speed_hz = 100000,
        };
        ESP_GOTO_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &ctx->dev_handle), err, TAG, "add I2C dev failed");
        tp->config.driver_data = (void *)ctx;
        ESP_LOGD(TAG, "I2C direct (addr=0x%02X)", ESP_LCD_TOUCH_IO_I2C_CST3530_ADDRESS);
    } else {
        ESP_LOGW(TAG, "No I2C bus handle in driver_data");
    }

    /* ---- GPIO init ---- */
    if (tp->config.rst_gpio_num != GPIO_NUM_NC) {
        gpio_reset_pin(tp->config.rst_gpio_num);
        gpio_set_direction(tp->config.rst_gpio_num, GPIO_MODE_OUTPUT);
    }

    if (tp->config.int_gpio_num != GPIO_NUM_NC) {
        gpio_reset_pin(tp->config.int_gpio_num);
        gpio_set_direction(tp->config.int_gpio_num, GPIO_MODE_OUTPUT);
        gpio_set_pull_mode(tp->config.int_gpio_num, GPIO_PULLUP_ONLY);
        gpio_set_level(tp->config.int_gpio_num, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    /* Reset */
    ret = touch_cst3530_reset(tp);
    ESP_GOTO_ON_ERROR(ret, err, TAG, "reset failed");

    /* Interrupt pin as input */
    if (tp->config.int_gpio_num != GPIO_NUM_NC) {
        gpio_reset_pin(tp->config.int_gpio_num);
        gpio_set_direction(tp->config.int_gpio_num, GPIO_MODE_INPUT);
        gpio_set_intr_type(tp->config.int_gpio_num,
                           tp->config.levels.interrupt ? GPIO_INTR_POSEDGE : GPIO_INTR_NEGEDGE);
        if (tp->config.interrupt_callback) {
            esp_lcd_touch_register_interrupt_callback(tp, tp->config.interrupt_callback);
        }
    }

    /* Identify chip */
    ret = touch_cst3530_read_cfg(tp);
    ESP_GOTO_ON_ERROR(ret, err, TAG, "init failed");

    *out_touch = tp;
    return ESP_OK;

err:
    if (ret != ESP_OK) {
        if (tp) {
            esp_lcd_touch_cst3530_del(tp);
        }
    }
    return ret;
}

static esp_err_t esp_lcd_touch_cst3530_enter_sleep(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_FALSE(tp != NULL, ESP_ERR_INVALID_ARG, TAG, "no handle");
    ESP_RETURN_ON_ERROR(touch_cst3530_pre_sleep(tp), TAG, "pre-sleep failed");
    return touch_cst3530_i2c_write_cmd(tp, ESP_LCD_TOUCH_CST3530_SLEEP_COMMAND);
}

static esp_err_t esp_lcd_touch_cst3530_exit_sleep(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_FALSE(tp != NULL, ESP_ERR_INVALID_ARG, TAG, "no handle");
    ESP_RETURN_ON_ERROR(touch_cst3530_reset(tp), TAG, "reset failed");
    ESP_RETURN_ON_ERROR(touch_cst3530_pre_sleep(tp), TAG, "pre-wake failed");
    ESP_RETURN_ON_ERROR(touch_cst3530_i2c_write_cmd(tp, 0xD0000000), TAG, "wake cmd 0 failed");
    ESP_RETURN_ON_ERROR(touch_cst3530_i2c_write_cmd(tp, 0xD0000C00), TAG, "wake cmd 1 failed");
    return touch_cst3530_i2c_write_cmd(tp, 0xD0000100);
}

static esp_err_t esp_lcd_touch_cst3530_read_data(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_FALSE(tp != NULL, ESP_ERR_INVALID_ARG, TAG, "no handle");

    esp_err_t ret;
    uint8_t buf[ESP_LCD_TOUCH_CST3530_MAX_READ_BYTES] = {0};
    uint8_t touch_cnt = 0;
    uint8_t key_number = 0;

    ret = touch_cst3530_i2c_read(tp, ESP_LCD_TOUCH_CST3530_READ_COMMAND, buf, sizeof(buf));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C read error");
        goto clear_and_fail;
    }

    if (buf[2] != 0xFF) {
        goto clear_and_ok;
    }

    touch_cnt = buf[3] & 0x0F;
    key_number = (buf[3] & 0xF0) >> 4;

    if (touch_cnt == 0 || touch_cnt > ESP_LCD_TOUCH_CST3530_MAX_FINGER_NUM) {
        goto clear_and_ok;
    }

    /* Verify checksum */
    uint16_t calc = touch_cst3530_checksum(0x55, &buf[4], (key_number + touch_cnt) * 5);
    uint16_t rcv  = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    if (calc != rcv) {
        ESP_LOGW(TAG, "Checksum 0x%04X != 0x%04X", calc, rcv);
        goto clear_and_fail;
    }

    portENTER_CRITICAL(&tp->data.lock);
    tp->data.points = 0;

    for (size_t i = 0; i < touch_cnt; i++) {
        uint16_t idx = (key_number + i) * 5;

        if (idx + CST3530_POINT_OFFSET_MAX >= ESP_LCD_TOUCH_CST3530_MAX_READ_BYTES) {
            break;
        }

        uint8_t event   = buf[idx + 8] >> 4;
        uint8_t pos_id  = buf[idx + 8] & 0x0F;
        uint8_t xy_high = buf[idx + 7];
        uint16_t pos_x  = (uint16_t)buf[idx + 4] | ((uint16_t)(xy_high & 0x0F) << 8);
        uint16_t pos_y  = (uint16_t)buf[idx + 5] | ((uint16_t)(xy_high & 0xF0) << 4);
        uint8_t press   = buf[idx + 6];

        if (event != 0x00) {
            uint8_t pt = tp->data.points;
            if (pt < CONFIG_ESP_LCD_TOUCH_MAX_POINTS) {
                /* track_id not in esp_lcd_touch v1.1.2 */
                tp->data.coords[pt].x         = pos_x;
                tp->data.coords[pt].y         = pos_y;
                tp->data.coords[pt].strength  = press;
                tp->data.points++;
            }
        }
    }
    portEXIT_CRITICAL(&tp->data.lock);

    touch_cst3530_i2c_write_cmd(tp, ESP_LCD_TOUCH_CST3530_CLEAR_COMMAND);
    return ESP_OK;

clear_and_fail:
    touch_cst3530_i2c_write_cmd(tp, ESP_LCD_TOUCH_CST3530_CLEAR_COMMAND);
    return ESP_FAIL;

clear_and_ok:
    touch_cst3530_i2c_write_cmd(tp, ESP_LCD_TOUCH_CST3530_CLEAR_COMMAND);
    return ESP_OK;
}

static bool esp_lcd_touch_cst3530_get_xy(esp_lcd_touch_handle_t tp, uint16_t *x, uint16_t *y, uint16_t *strength,
                                       uint8_t *point_num, uint8_t max_point_num)
{
    ESP_RETURN_ON_FALSE(tp, false, TAG, "no handle");
    ESP_RETURN_ON_FALSE(x && y && point_num, false, TAG, "bad args");

    portENTER_CRITICAL(&tp->data.lock);
    *point_num = (tp->data.points > max_point_num) ? max_point_num : tp->data.points;
    for (size_t i = 0; i < *point_num; i++) {
        x[i] = tp->data.coords[i].x;
        y[i] = tp->data.coords[i].y;
        if (strength) {
            strength[i] = tp->data.coords[i].strength;
        }
    }
    portEXIT_CRITICAL(&tp->data.lock);
    return (*point_num > 0);
}

/* get_track_id not available in esp_lcd_touch v1.1.2 — function removed */

#if (CONFIG_ESP_LCD_TOUCH_MAX_BUTTONS > 0)
static esp_err_t esp_lcd_touch_cst3530_get_button_state(esp_lcd_touch_handle_t tp, uint8_t n, uint8_t *state)
{
    ESP_RETURN_ON_FALSE(tp, ESP_ERR_INVALID_ARG, TAG, "no handle");
    ESP_RETURN_ON_FALSE(state, ESP_ERR_INVALID_ARG, TAG, "bad args");

    *state = 0;
    portENTER_CRITICAL(&tp->data.lock);
    esp_err_t err = ESP_OK;
    if (n > tp->data.buttons) {
        err = ESP_ERR_INVALID_ARG;
    } else {
        *state = tp->data.button[n].status;
    }
    portEXIT_CRITICAL(&tp->data.lock);
    return err;
}
#endif

static esp_err_t esp_lcd_touch_cst3530_del(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_FALSE(tp, ESP_ERR_INVALID_ARG, TAG, "no handle");

    cst3530_i2c_ctx_t *ctx = (cst3530_i2c_ctx_t *)tp->config.driver_data;
    if (ctx) {
        if (ctx->dev_handle) {
            i2c_master_bus_rm_device(ctx->dev_handle);
        }
        free(ctx);
        tp->config.driver_data = NULL;
    }

    if (tp->config.int_gpio_num != GPIO_NUM_NC) {
        gpio_reset_pin(tp->config.int_gpio_num);
        if (tp->config.interrupt_callback) {
            gpio_isr_handler_remove(tp->config.int_gpio_num);
        }
    }
    if (tp->config.rst_gpio_num != GPIO_NUM_NC) {
        gpio_reset_pin(tp->config.rst_gpio_num);
    }

    free(tp);
    return ESP_OK;
}

/*******************************************************************************
* Private helpers
*******************************************************************************/

static uint16_t touch_cst3530_checksum(uint16_t init_val, const uint8_t *buf, uint16_t len)
{
    uint16_t sum = init_val;
    while (len--) {
        sum += *buf++;
    }
    return sum;
}

static esp_err_t touch_cst3530_reset(esp_lcd_touch_handle_t tp)
{
    if (tp->config.rst_gpio_num != GPIO_NUM_NC) {
        gpio_set_level(tp->config.rst_gpio_num, tp->config.levels.reset);
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level(tp->config.rst_gpio_num, !tp->config.levels.reset);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return ESP_OK;
}

static esp_err_t touch_cst3530_read_cfg(esp_lcd_touch_handle_t tp)
{
    ESP_RETURN_ON_FALSE(tp, ESP_ERR_INVALID_ARG, TAG, "no handle");

    uint8_t buf[50];
    int retry = 5;

    while (retry--) {
        esp_err_t ret = touch_cst3530_i2c_read(tp, ESP_LCD_TOUCH_CST3530_INFO_COMMAND, buf, sizeof(buf));
        if (ret != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (buf[2] == 0xCA && buf[3] == 0xCA) {
            uint32_t chip_id = ((uint32_t)buf[3] << 24) | ((uint32_t)buf[2] << 16) |
                               ((uint32_t)buf[1] << 8) | buf[0];
            uint16_t res_x = ((uint16_t)buf[29] << 8) | buf[28];
            uint16_t res_y = ((uint16_t)buf[31] << 8) | buf[30];

            ESP_LOGI(TAG, "CST3530 ID=0x%08"PRIX32" %dx%d fw=0x%08X key=%d",
                     chip_id, res_x, res_y,
                     ((uint32_t)buf[35] << 24) | ((uint32_t)buf[34] << 16) |
                     ((uint32_t)buf[33] << 8) | buf[32],
                     buf[27]);
            if (buf[48] || buf[49]) {
                ESP_LOGI(TAG, "Tx=%d Rx=%d", buf[48], buf[49]);
            }
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    ESP_LOGE(TAG, "read_cfg failed after retries");
    return ESP_FAIL;
}

static esp_err_t touch_cst3530_i2c_read(esp_lcd_touch_handle_t tp, uint32_t cmd, uint8_t *data, uint8_t len)
{
    ESP_RETURN_ON_FALSE(tp && data, ESP_ERR_INVALID_ARG, TAG, "bad args");

    cst3530_i2c_ctx_t *ctx = (cst3530_i2c_ctx_t *)tp->config.driver_data;
    ESP_RETURN_ON_FALSE(ctx && ctx->dev_handle, ESP_ERR_INVALID_STATE, TAG, "I2C ctx not ready");

    uint8_t cmd_buf[4];
    pack_cmd(cmd, cmd_buf);
    return i2c_master_transmit_receive(ctx->dev_handle, cmd_buf, 4, data, len, -1);
}

static esp_err_t touch_cst3530_i2c_write_cmd(esp_lcd_touch_handle_t tp, uint32_t cmd)
{
    ESP_RETURN_ON_FALSE(tp, ESP_ERR_INVALID_ARG, TAG, "bad args");

    cst3530_i2c_ctx_t *ctx = (cst3530_i2c_ctx_t *)tp->config.driver_data;
    ESP_RETURN_ON_FALSE(ctx && ctx->dev_handle, ESP_ERR_INVALID_STATE, TAG, "I2C ctx not ready");

    uint8_t cmd_buf[4];
    pack_cmd(cmd, cmd_buf);
    return i2c_master_transmit(ctx->dev_handle, cmd_buf, 4, -1);
}
