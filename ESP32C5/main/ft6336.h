#ifndef FT6336_H
#define FT6336_H

#include "driver/i2c.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

// FT6336U I2C Address
#define FT6336_I2C_ADDR 0x38

// FT6336U Register Addresses
#define FT6336_REG_MODE         0x00
#define FT6336_REG_TD_STATUS    0x02
#define FT6336_REG_TOUCH1_XH    0x03
#define FT6336_REG_TOUCH1_XL    0x04
#define FT6336_REG_TOUCH1_YH    0x05
#define FT6336_REG_TOUCH1_YL    0x06
#define FT6336_REG_TOUCH2_XH    0x09
#define FT6336_REG_TOUCH2_XL    0x0A
#define FT6336_REG_TOUCH2_YH    0x0B
#define FT6336_REG_TOUCH2_YL    0x0C
#define FT6336_REG_CHIPID       0xA3
#define FT6336_REG_FIRMID       0xA6
#define FT6336_REG_VENDID       0xA8

// Expected chip ID for FT6336U
#define FT6336_CHIP_ID          0x64

// Touch point structure
typedef struct {
    uint16_t x;
    uint16_t y;
    bool touched;
} ft6336_touch_point_t;

// FT6336 Handle structure
typedef struct {
    i2c_port_t i2c_port;
    int int_gpio;
    int rst_gpio;
    uint16_t width;
    uint16_t height;
} ft6336_handle_t;

/**
 * @brief Initialize FT6336U touch controller
 * 
 * @param handle Pointer to FT6336 handle structure
 * @param i2c_port I2C port number (I2C_NUM_0 or I2C_NUM_1)
 * @param int_gpio Interrupt GPIO pin (active LOW when touched), or -1 if not used
 * @param rst_gpio Reset GPIO pin (active LOW), or -1 if not used
 * @param width Screen width in pixels
 * @param height Screen height in pixels
 * @return esp_err_t ESP_OK on success
 */
esp_err_t ft6336_init(ft6336_handle_t *handle, i2c_port_t i2c_port,
                      int int_gpio, int rst_gpio, uint16_t width, uint16_t height);

/**
 * @brief Read touch point data from FT6336U
 * 
 * @param handle Pointer to FT6336 handle
 * @param point Pointer to touch point structure to store result
 * @return true if touch detected, false otherwise
 */
bool ft6336_read_touch(ft6336_handle_t *handle, ft6336_touch_point_t *point);

/**
 * @brief Read multiple touch points (up to 2)
 * 
 * @param handle Pointer to FT6336 handle
 * @param points Array of touch point structures (size >= 2)
 * @param max_points Maximum number of points to read (typically 2)
 * @return Number of touch points detected (0-2)
 */
int ft6336_read_multi_touch(ft6336_handle_t *handle, ft6336_touch_point_t *points, int max_points);

/**
 * @brief Check if screen is currently touched
 * 
 * @param handle Pointer to FT6336 handle
 * @return true if touched, false otherwise
 */
bool ft6336_is_touched(ft6336_handle_t *handle);

/**
 * @brief Get chip ID from FT6336U
 * 
 * @param handle Pointer to FT6336 handle
 * @return Chip ID value, or 0 on error
 */
uint8_t ft6336_get_chip_id(ft6336_handle_t *handle);

#endif // FT6336_H

