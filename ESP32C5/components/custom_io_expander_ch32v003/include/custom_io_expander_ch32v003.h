/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief ESP IO expander: TCA9554
 */

#pragma once

#include <stdint.h>
#include "esp_err.h"
#include "driver/i2c_master.h"
#include "esp_io_expander.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a CH32V003 IO expander object
 *
 * @param[in]  i2c_bus    I2C bus handle. Obtained from `i2c_new_master_bus()`
 * @param[in]  dev_addr   I2C device address of chip. Can be `CUSTOM_IO_EXPANDER_I2C_CH32V003_ADDRESS_XXX`.
 * @param[out] handle_ret Handle to created IO expander object
 *
 * @return
 *      - ESP_OK: Success, otherwise returns ESP_ERR_xxx
 */
esp_err_t custom_io_expander_new_i2c_ch32v003(i2c_master_bus_handle_t i2c_bus, uint32_t dev_addr, esp_io_expander_handle_t *handle_ret);

/**
 * @brief Create a CH32V003 IO expander object
 *
 * @param[in]  i2c_bus    I2C bus handle. Obtained from `i2c_new_master_bus()`
 * @param[in]  dev_addr   I2C device address of chip. Can be `CUSTOM_IO_EXPANDER_I2C_CH32V003_ADDRESS_XXX`.
 * @param[out] handle_ret Handle to created IO expander object
 *
 * @return
 *      - ESP_OK: Success, otherwise returns ESP_ERR_xxx
 */
esp_err_t custom_io_expander_new_i2c_ch32v003(i2c_master_bus_handle_t i2c_bus, uint32_t dev_addr, esp_io_expander_handle_t *handle_ret);

/**
 * @brief Set PWM output for the custom IO chip 
 *
 * @param[in]  value    PWM duty cycle value （0~255）
 *
 * @return
 *      - ESP_OK: Success, otherwise returns ESP_ERR_xxx
 */
esp_err_t custom_io_expander_set_pwm(esp_io_expander_t *handle, uint8_t value);

/**
 * @brief Get ADC value from the custom IO chip
 *
 * @param[out] adc_value    Retrieved ADC value （0~1023)
 *
 * @return
 *      - ESP_OK: Success, otherwise returns ESP_ERR_xxx
 */
esp_err_t custom_io_expander_get_adc(esp_io_expander_t *handle, uint16_t *adc_value);

/**
 * @brief Get interrupt status from the custom IO chip
 *
 * @param[out] int_value    Retrieved interrupt status (0 or 1)
 *
 * @return
 *      - ESP_OK: Success, otherwise returns ESP_ERR_xxx
 */
esp_err_t custom_io_expander_get_int(esp_io_expander_t *handle, uint8_t *int_value);


/**
 * @brief I2C address of the CH32V003
 */
#define CUSTOM_IO_EXPANDER_I2C_CH32V003_ADDRESS    (0x24)

#ifdef __cplusplus
}
#endif
