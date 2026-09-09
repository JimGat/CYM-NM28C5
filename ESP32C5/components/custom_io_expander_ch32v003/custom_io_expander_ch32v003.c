/*
 * SPDX-FileCopyrightText: 2023-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "esp_bit_defs.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_io_expander.h"
#include "custom_io_expander_ch32v003.h"

/* I2C communication related */
#define I2C_TIMEOUT_MS          (1000)
#define I2C_CLK_SPEED           (400000)

#define IO_COUNT                (8)

/* Register address */
#define DIRECTION_REG_ADDR      (0x02)
#define OUTPUT_REG_ADDR         (0x03)
#define INPUT_REG_ADDR          (0x04)
#define PWM_REG_ADDR            (0x05)
#define ADC_REG_ADDR            (0x06)
#define RTC_REG_ADDR            (0x07)

/* Default register value on power-up */
#define DIR_REG_DEFAULT_VAL     (0xff)
#define OUT_REG_DEFAULT_VAL     (0x00)

/**
 * @brief Device Structure Type
 *
 */
typedef struct {
    esp_io_expander_t base;
    i2c_master_dev_handle_t i2c_handle;
    struct {
        uint8_t direction;
        uint8_t output;
    } regs;
} custom_io_expander_ch32v003_t;

static char *TAG = "custom_io";

static esp_err_t read_input_reg(esp_io_expander_handle_t handle, uint32_t *value);
static esp_err_t write_output_reg(esp_io_expander_handle_t handle, uint32_t value);
static esp_err_t read_output_reg(esp_io_expander_handle_t handle, uint32_t *value);
static esp_err_t write_direction_reg(esp_io_expander_handle_t handle, uint32_t value);
static esp_err_t read_direction_reg(esp_io_expander_handle_t handle, uint32_t *value);
static esp_err_t reset(esp_io_expander_t *handle);
static esp_err_t del(esp_io_expander_t *handle);

esp_err_t custom_io_expander_new_i2c_ch32v003(i2c_master_bus_handle_t i2c_bus, uint32_t dev_addr, esp_io_expander_handle_t *handle_ret)
{
    ESP_RETURN_ON_FALSE(handle_ret != NULL, ESP_ERR_INVALID_ARG, TAG, "Invalid handle_ret");

    // Allocate memory for driver object
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)calloc(1, sizeof(custom_io_expander_ch32v003_t));
    ESP_RETURN_ON_FALSE(custom_io != NULL, ESP_ERR_NO_MEM, TAG, "Malloc failed");

    // Add new I2C device
    esp_err_t ret = ESP_OK;
    const i2c_device_config_t i2c_dev_cfg = {
        .device_address = dev_addr,
        .scl_speed_hz = I2C_CLK_SPEED,
    };
    ESP_GOTO_ON_ERROR(i2c_master_bus_add_device(i2c_bus, &i2c_dev_cfg, &custom_io->i2c_handle), err, TAG, "Add new I2C device failed");

    custom_io->base.config.io_count = IO_COUNT;
    custom_io->base.config.flags.dir_out_bit_zero = 0;
    custom_io->base.read_input_reg = read_input_reg;
    custom_io->base.write_output_reg = write_output_reg;
    custom_io->base.read_output_reg = read_output_reg;
    custom_io->base.write_direction_reg = write_direction_reg;
    custom_io->base.read_direction_reg = read_direction_reg;
    custom_io->base.del = del;
    custom_io->base.reset = reset;

    /* Reset configuration and register status */
    ESP_GOTO_ON_ERROR(reset(&custom_io->base), err1, TAG, "Reset failed");

    *handle_ret = &custom_io->base;
    return ESP_OK;
err1:
    i2c_master_bus_rm_device(custom_io->i2c_handle);
err:
    free(custom_io);
    return ret;
}

static esp_err_t read_input_reg(esp_io_expander_handle_t handle, uint32_t *value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);

    uint8_t temp = 0;
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(custom_io->i2c_handle, (uint8_t[]) {
        INPUT_REG_ADDR
    }, 1, &temp, sizeof(temp), I2C_TIMEOUT_MS), TAG, "Read input reg failed");
    *value = temp;
    return ESP_OK;
}

static esp_err_t write_output_reg(esp_io_expander_handle_t handle, uint32_t value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);
    value &= 0xff;

    uint8_t data[] = {OUTPUT_REG_ADDR, value};
    ESP_RETURN_ON_ERROR(i2c_master_transmit(custom_io->i2c_handle, data, sizeof(data), I2C_TIMEOUT_MS), TAG, "Write output reg failed");
    custom_io->regs.output = value;
    return ESP_OK;
}

static esp_err_t read_output_reg(esp_io_expander_handle_t handle, uint32_t *value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);

    *value = custom_io->regs.output;
    return ESP_OK;
}

static esp_err_t write_direction_reg(esp_io_expander_handle_t handle, uint32_t value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);
    value &= 0xff;

    uint8_t data[] = {DIRECTION_REG_ADDR, value};
    ESP_RETURN_ON_ERROR(i2c_master_transmit(custom_io->i2c_handle, data, sizeof(data), I2C_TIMEOUT_MS), TAG, "Write direction reg failed");
    custom_io->regs.direction = value;
    return ESP_OK;
}

static esp_err_t read_direction_reg(esp_io_expander_handle_t handle, uint32_t *value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);
    *value = custom_io->regs.direction;
    return ESP_OK;
}

static esp_err_t reset(esp_io_expander_t *handle)
{
    ESP_RETURN_ON_ERROR(write_direction_reg(handle, DIR_REG_DEFAULT_VAL), TAG, "Write dir reg failed");
    ESP_RETURN_ON_ERROR(write_output_reg(handle, OUT_REG_DEFAULT_VAL), TAG, "Write output reg failed");
    return ESP_OK;
}

static esp_err_t del(esp_io_expander_t *handle)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);

    ESP_RETURN_ON_ERROR(i2c_master_bus_rm_device(custom_io->i2c_handle), TAG, "Remove I2C device failed");
    free(custom_io);
    return ESP_OK;
}

esp_err_t custom_io_expander_set_pwm(esp_io_expander_t *handle, uint8_t value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);

    uint8_t data[] = {PWM_REG_ADDR, value};
    ESP_RETURN_ON_ERROR(i2c_master_transmit(custom_io->i2c_handle, data, sizeof(data), I2C_TIMEOUT_MS), TAG, "Write pwm reg failed");
    return ESP_OK;
}

esp_err_t custom_io_expander_get_adc(esp_io_expander_t *handle, uint16_t *adc_value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);
    uint8_t temp[2] = {0};
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(custom_io->i2c_handle, (uint8_t[]) {
        ADC_REG_ADDR
    }, 1, temp, sizeof(temp), I2C_TIMEOUT_MS), TAG, "Read adc reg failed");
    *adc_value = temp[1] << 8 | temp[0];
    return ESP_OK;
}

esp_err_t custom_io_expander_get_int(esp_io_expander_t *handle, uint8_t *int_value)
{
    custom_io_expander_ch32v003_t *custom_io = (custom_io_expander_ch32v003_t *)__containerof(handle, custom_io_expander_ch32v003_t, base);
    uint8_t temp = 0;
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(custom_io->i2c_handle, (uint8_t[]) {
        RTC_REG_ADDR
    }, 1, &temp, sizeof(temp), I2C_TIMEOUT_MS), TAG, "Read adc reg failed");
    *int_value = temp;
    return ESP_OK;
}
